"""Scan orchestration: collect, evaluate, score, verdict, persist."""

from __future__ import annotations

import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from claude_sentinel import __version__, scoring
from claude_sentinel.collectors import (
    account as account_collector,
)
from claude_sentinel.collectors import (
    behavior as behavior_collector,
)
from claude_sentinel.collectors import (
    claude_code,
    ip_intel,
    local,
    netmode,
    network,
    official,
    rdap,
    rpki,
    runtimes,
)
from claude_sentinel.collectors.base import Http, cache_read
from claude_sentinel.config import Settings, load_weights
from claude_sentinel.history import HistoryStore
from claude_sentinel.models import (
    AccountState,
    BrowserProbe,
    Confidence,
    EnvironmentSummary,
    IpConsensus,
    Observation,
    Profile,
    Report,
    Source,
    Status,
    VerdictCode,
)
from claude_sentinel.progress import ProgressFn, Tracker
from claude_sentinel.redact import mask_ip
from claude_sentinel.rules import evaluate
from claude_sentinel.rules.context import Context, GateInfo
from claude_sentinel.scoring import min_confidence, score_findings
from claude_sentinel.verdict import build_verdict

DISCLAIMERS = [
    "本工具不是 Anthropic 官方产品，无法读取 Anthropic 内部风控、黑名单、支付或服务端历史。",
    "安全分是启发式，不是封号概率；没有官方账号信号时只应表述为“未知/风险”。",
    "账号层未提供凭据时为未知；环境层通过不代表账号安全。",
    "不受支持地区：官方政策不允许使用；本工具不提供时区/语言/指纹伪装等规避方案。",
]


def _dedupe_sources(sources: list[Source]) -> list[Source]:
    seen: set[tuple[str, str | None, str]] = set()
    out: list[Source] = []
    for source in sources:
        key = (source.name, source.url, str(source.kind))
        if key in seen:
            continue
        seen.add(key)
        out.append(source)
    return out


def load_profile(path: Path) -> Profile | None:
    if not path.exists():
        return None
    try:
        return Profile.model_validate_json(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _load_account_cache(settings: Settings) -> AccountState | None:
    cached = cache_read(settings.cache_dir, "account_state", 24 * 3600)
    if not cached:
        return None
    try:
        return AccountState.model_validate(cached)
    except Exception:
        return None


def _load_browser_probe(settings: Settings) -> BrowserProbe | None:
    cached = cache_read(settings.cache_dir, "browser_probe", 15 * 60)
    if not cached:
        return None
    try:
        return BrowserProbe.model_validate(cached)
    except Exception:
        return None


def _minimal_consensus(ip: str | None, trace: Observation | None) -> IpConsensus | None:
    if not ip:
        return None
    loc = None
    if trace and isinstance(trace.value, dict):
        loc = trace.value.get("loc")
    return IpConsensus(
        ip=ip,
        country_code=str(loc).upper() if loc else None,
        providers_ok=0,
        providers_total=0,
    )


def _trace_loc(trace: Observation | None) -> str | None:
    if trace and isinstance(trace.value, dict):
        loc = trace.value.get("loc")
        if loc:
            return str(loc).upper()
    return None


def _observe(observations: dict[str, Observation], items: list[Observation] | Observation) -> None:
    if isinstance(items, Observation):
        items = [items]
    for item in items:
        observations[item.key] = item


def run_scan(
    settings: Settings,
    http: Http | None = None,
    store: HistoryStore | None = None,
    progress: ProgressFn | None = None,
) -> Report:
    settings.ensure()
    started_at = datetime.now(timezone.utc)
    store = store or HistoryStore(settings.db_path)
    tracker = Tracker(progress)

    if settings.offline:
        last = store.last()
        if not last or not last.get("report_json"):
            raise RuntimeError("没有可用的历史报告；offline 模式至少需要先成功运行一次")
        return Report.model_validate_json(last["report_json"])

    own_http = http is None
    client = http or Http(proxy=settings.proxy, timeout=settings.timeout)
    observations: dict[str, Observation] = {}
    errors: list[str] = []

    try:
        with tracker.stage("gate") as stage:
            region_obs = official.check_region_gate(client)
            value = region_obs.value if isinstance(region_obs.value, dict) else {}
            available = value.get("available")
            if available is True:
                stage.done("区域闸门通过")
            elif available is False:
                stage.warn(f"官方返回 {value.get('error_code') or 'region_unavailable'}")
            else:
                stage.warn("无法判断（网络/Cloudflare）")

        with tracker.stage("regions") as stage:
            regions, regions_obs = official.load_regions(client, settings)
            stage.done(f"{len(regions.codes)} 个支持地区")

        with tracker.stage("service") as stage:
            service, status_obs = official.check_status(client, settings)
            stage.done("operational" if service.relevant_ok else service.indicator)

        with tracker.stage("clock") as stage:
            clock_obs = official.check_clock(client)
            offset = clock_obs.value if isinstance(clock_obs.value, (int, float)) else None
            stage.done("偏差正常" if offset is None or abs(offset) <= 300 else f"偏差 {offset:+.0f}s")

        with tracker.stage("reach") as stage:
            reach_obs = official.check_reachability(client)
            ok = sum(1 for obs in reach_obs if obs.status == Status.ok)
            (stage.done if ok == len(reach_obs) else stage.warn)(f"{ok}/{len(reach_obs)} 可达")

        _observe(observations, [region_obs, regions_obs, status_obs, clock_obs, *reach_obs])

        with tracker.stage("edge") as stage:
            # Probe every relevant domain: proxy rules are per-domain, so the
            # generic Cloudflare probe is NOT a proxy for what Claude sees.
            trace_obs_list = network.collect_traces(client)
            traces = [network.trace_model(obs) for obs in trace_obs_list]
            # Authoritative view first, then the other Anthropic hostnames,
            # then the generic probe: a blocked claude.ai must not blind us.
            claude_trace = None
            for key in ("trace.claude", "trace.anthropic", "trace.api", "trace.cf"):
                claude_trace = next((t for t in traces if t.key == key and t.ok and t.loc), None)
                if claude_trace:
                    break
            trace_obs = next(
                (obs for obs in trace_obs_list if obs.key == network.PRIMARY_TRACE_KEY),
                trace_obs_list[0] if trace_obs_list else None,
            )
            if claude_trace:
                mismatched = [t for t in traces if t.ok and t.loc and t.loc.upper() != claude_trace.loc.upper()]
                if mismatched:
                    stage.warn(
                        f"{claude_trace.domain or claude_trace.key} {claude_trace.loc}，但 "
                        + "/".join(f"{t.domain or t.key} {t.loc}" for t in mismatched)
                        + " 不一致"
                    )
                elif claude_trace.key != "trace.claude":
                    stage.warn(f"claude.ai 不可达，改用 {claude_trace.domain or claude_trace.key} {claude_trace.loc}")
                else:
                    stable = all(t.ip == claude_trace.ip for t in traces if t.ok and t.loc)
                    stage.done(
                        f"claude.ai {claude_trace.loc} · {mask_ip(claude_trace.ip)}"
                        + ("" if stable else " · IP 因域名而异")
                    )
            else:
                stage.warn("所有域名的边缘 trace 都不可达")

        with tracker.stage("dual") as stage:
            dual_obs = network.collect_dual_stack(settings.proxy)
            reachable = sum(1 for obs in dual_obs if obs.status == Status.ok)
            (stage.done if reachable else stage.warn)(f"{reachable}/2 个协议可达")

        with tracker.stage("dns") as stage:
            dns_obs = network.collect_dns(client)
            dns_value = dns_obs.value if isinstance(dns_obs.value, dict) else {}
            (stage.done if dns_value.get("ip") else stage.warn)(str(dns_value.get("geo") or "不可达"))

        _observe(observations, [*trace_obs_list, dns_obs, *dual_obs])

        with tracker.stage("local") as stage:
            local_info, local_obs = local.collect_local(settings.home)
            network_mode, mode_obs = netmode.collect_network_mode()
            runtime_probes, runtime_obs = runtimes.collect_runtimes()
            node_probe = next((p for p in runtime_probes if p.runtime == "node" and p.ok), None)
            node_note = ""
            if node_probe and node_probe.loc and claude_trace and claude_trace.ok and claude_trace.loc:
                if node_probe.loc.upper() != claude_trace.loc.upper():
                    node_note = f" · Node 走 {node_probe.loc}（与浏览器不同）"
            if network_mode.tun_active:
                stage.done(f"TUN {network_mode.tun_interface}{node_note}")
            elif network_mode.system_proxy_enabled:
                (stage.warn if node_note else stage.done)(
                    f"系统代理（终端可能绕过）{node_note}"
                )
            else:
                stage.warn(f"直连（无 TUN/代理）{node_note}")

        with tracker.stage("client") as stage:
            cc_info, cc_obs = claude_code.collect_claude_code()
            if not cc_info.installed:
                stage.warn("未检测到 Claude Code")
            elif cc_info.base_url_kind == "third_party":
                stage.warn(f"第三方端点 {cc_info.relay_hint or ''}".strip())
            else:
                stage.done(f"v{cc_info.version or '?'} · {cc_info.base_url_kind}")

        _observe(observations, [*local_obs, *cc_obs, *mode_obs, *runtime_obs])

        # What Claude itself sees is the primary egress. Fall back to the
        # generic Cloudflare probe, then the dual-stack probes, only when
        # claude.ai's own trace is unreachable.
        claude_ip = claude_trace.ip if claude_trace and claude_trace.ok else None
        cf_trace = next((t for t in traces if t.key == "trace.cf" and t.ok), None)
        edge_ip = claude_ip or (cf_trace.ip if cf_trace else None) or network.edge_ip(trace_obs)
        v4_obs = observations.get("net.v4")
        v6_obs = observations.get("net.v6")
        v4_ip = (v4_obs.value or {}).get("ip") if v4_obs and isinstance(v4_obs.value, dict) else None
        v6_ip = (v6_obs.value or {}).get("ip") if v6_obs and isinstance(v6_obs.value, dict) else None
        primary_ip = edge_ip or v6_ip or v4_ip

        if settings.ip_intel and primary_ip:
            lookups: dict[str, IpConsensus] = {}
            targets = {}
            if primary_ip:
                targets["primary"] = primary_ip
            if v4_ip and v4_ip != primary_ip:
                targets["v4"] = v4_ip
            if v6_ip and v6_ip != primary_ip:
                targets["v6"] = v6_ip
            with tracker.stage("ipintel") as stage:
                with ThreadPoolExecutor(max_workers=max(1, len(targets))) as pool:
                    futures = {
                        key: pool.submit(ip_intel.lookup_ip, ip, client, settings)
                        for key, ip in targets.items()
                    }
                    for key, future in futures.items():
                        try:
                            lookups[key] = future.result()
                        except Exception as exc:  # noqa: BLE001
                            errors.append(f"ip_intel.{key}: {exc}")
                consensus = lookups.get("primary")
                ok = consensus.providers_ok if consensus else 0
                total = consensus.providers_total if consensus else 0
                if consensus and consensus.country_code:
                    stage.done(f"{consensus.country_code} · {ok}/{total} 源一致")
                else:
                    stage.warn(f"{ok}/{total} 源可用")
            primary = lookups.get("primary")
            ipv4 = lookups.get("v4") or (lookups.get("primary") if primary_ip == v4_ip else None)
            ipv6 = lookups.get("v6") or (lookups.get("primary") if primary_ip == v6_ip else None)
        else:
            primary = _minimal_consensus(primary_ip, trace_obs)
            ipv4 = _minimal_consensus(v4_ip, v4_obs)
            ipv6 = _minimal_consensus(v6_ip, v6_obs)
            tracker.emit("ipintel", "skip", "已跳过第三方情报", 0)

        if primary:
            _observe(observations, ip_intel.consensus_observation(primary))
        if ipv4 and (not primary or ipv4.ip != primary.ip):
            _observe(
                observations,
                ip_intel.consensus_observation(ipv4, key="ip.v4", label="IPv4 出口情报"),
            )
        if ipv6 and (not primary or ipv6.ip != primary.ip):
            _observe(
                observations,
                ip_intel.consensus_observation(ipv6, key="ip.v6", label="IPv6 出口情报"),
            )

        with tracker.stage("rdap") as stage:
            rdap_info = rdap.lookup_rdap(primary_ip, client, settings) if primary_ip else None
            if rdap_info and rdap_info.ok:
                stage.done(
                    f"{rdap_info.network_name or rdap_info.handle or '—'} · "
                    f"{rdap_info.registration or '注册时间未知'}"
                )
            else:
                stage.warn(rdap_info.error if rdap_info and rdap_info.error else "注册信息不可达")
        if rdap_info:
            _observe(observations, rdap.rdap_observation(rdap_info))

        with tracker.stage("rpki") as stage:
            rpki_info = rpki.lookup_rpki(primary_ip, client, settings)
            if rpki_info is None:
                stage.skip("没有出口 IP，跳过前缀校验")
            elif not rpki_info.ok:
                stage.warn(rpki_info.error or "RPKI 数据不可达")
            elif rpki_info.status == "valid":
                stage.done(f"{rpki_info.prefix or '前缀'} · RPKI 有效")
            else:
                stage.warn(f"{rpki_info.prefix or '前缀'} · RPKI {rpki_info.status or '未知'}")
        rpki_obs = rpki.rpki_observation(rpki_info)
        if rpki_obs:
            _observe(observations, rpki_obs)

        with tracker.stage("account") as stage:
            account_state: AccountState | None = None
            if settings.account_token:
                account_state = account_collector.probe_oauth(
                    settings.account_token, client, settings.account_ua
                )
            elif settings.account_cookie:
                account_state = account_collector.probe_cookie(
                    settings.account_cookie, client, settings.account_ua
                )
            else:
                account_state = _load_account_cache(settings)
            if account_state is None:
                stage.skip("参考模式：未提供凭据")
            elif account_state.state == "active":
                stage.done(f"active · {account_state.plan or '未提供套餐'}")
            else:
                stage.warn(account_state.detail or account_state.state)
        if account_state:
            _observe(
                observations,
                Observation(
                    key="account.state",
                    label="账号状态",
                    value={"state": account_state.state, "plan": account_state.plan},
                    status=(
                        Status.ok
                        if account_state.state == "active"
                        else (Status.high if account_state.state == "disabled" else Status.warn)
                    ),
                    source=account_state.source
                    or Source(
                        name="Claude account endpoint",
                        kind="official",
                        url="https://claude.ai/api/organizations",
                    ),
                    visibility="server",
                    detail=account_state.detail or account_state.state,
                ),
            )

        behavior_data = behavior_collector.collect_behavior() if settings.deep else None
        browser_probe = _load_browser_probe(settings)
        if browser_probe:
            _observe(
                observations,
                Observation(
                    key="browser.probe",
                    label="浏览器探针",
                    value={
                        "egress_ip": browser_probe.egress_ip,
                        "egress_country": browser_probe.egress_country,
                        "timezone": browser_probe.timezone,
                        "webrtc": len(browser_probe.webrtc),
                    },
                    status=Status.ok,
                    source=Source(
                        name="Local browser probe",
                        kind="local",
                        confidence=Confidence.high,
                    ),
                    visibility="browser_js",
                    detail=(
                        f"{browser_probe.egress_ip or '?'} · "
                        f"{browser_probe.egress_country or '?'} · "
                        f"{browser_probe.timezone or '?'}"
                    ),
                ),
            )

        profile = load_profile(settings.profile_path)
        history = store.summary()
        account_value = account_state.state if account_state else "unknown"

        current_fields = {
            "ip": primary_ip,
            "country": (primary.country_code if primary else None) or _trace_loc(trace_obs),
            "asn": primary.asn if primary else None,
            "timezone": local_info.timezone,
            "browser": local_info.browsers[0] if local_info.browsers else None,
            "fingerprint": local_info.machine_fingerprint,
            "account_state": account_value,
            "verdict": None,
            "score": None,
        }
        last = store.last()
        with tracker.stage("history") as stage:
            history.drift = store.compute_drift(current_fields, last)
            changed = [d for d in history.drift if d.changed]
            if history.is_baseline:
                stage.done("首次运行 · 已记录基线")
            elif changed:
                labels = "、".join(d.label for d in changed[:3])
                stage.warn(f"{len(changed)} 项变化 · {labels}")
            else:
                stage.done("与上次一致")

        region_value = region_obs.value if isinstance(region_obs.value, dict) else {}
        gate_available = region_value.get("available")
        gate = GateInfo(
            region_available=gate_available if isinstance(gate_available, bool) else None,
            region_error_code=region_value.get("error_code"),
            region_detail=region_obs.detail,
            status_ok=service.relevant_ok if service.indicator != "unknown" else None,
            clock_offset=clock_obs.value if isinstance(clock_obs.value, (int, float)) else None,
        )

        ctx = Context(
            settings=settings,
            observations=observations,
            ip=primary,
            ipv4=ipv4,
            ipv6=ipv6,
            rdap=rdap_info,
            regions=regions,
            status=service,
            account=account_state,
            profile=profile,
            client=cc_info,
            local=local_info,
            browser=browser_probe,
            behavior=behavior_data,
            history=history,
            gate=gate,
            traces=traces,
            rpki=rpki_info,
            network_mode=network_mode,
            runtimes=runtime_probes,
        )

        with tracker.stage("score") as stage:
            findings = evaluate(ctx)
            weights = load_weights()
            categories, score, level, coverage, confidence = score_findings(findings, weights)
            score_basis = dict(scoring.SCORE_BASIS)

            if account_state is None or account_state.state in {"challenge", "unknown"}:
                confidence = min_confidence(confidence, Confidence.medium)
            if primary is not None and primary.providers_ok < 2 and settings.ip_intel:
                confidence = min_confidence(confidence, Confidence.medium)
            if gate_available is None:
                confidence = min_confidence(confidence, Confidence.medium)

            risky = sum(1 for f in findings if f.status in {Status.high, Status.warn})
            stage.done(f"{len(findings)} 条规则 · {risky} 条命中 · 覆盖率 {coverage * 100:.0f}%")

        with tracker.stage("verdict") as stage:
            verdict = build_verdict(ctx, findings, score, level, coverage, confidence)
            stage.done(verdict.headline)

        current_fields["verdict"] = verdict.headline
        current_fields["score"] = score
        drift = store.compute_drift(current_fields, last)
        history.drift = drift

        blocked = verdict.code in {
            VerdictCode.blocked_account,
            VerdictCode.blocked_region,
            VerdictCode.blocked_service,
            VerdictCode.blocked_clock,
        }
        unknown = verdict.code == VerdictCode.unknown
        report_score = None if (blocked or unknown) else score
        report_level = "blocked" if blocked else ("unknown" if unknown else level)

        env = EnvironmentSummary(
            ip=primary_ip,
            ip_masked=mask_ip(primary_ip),
            ipv6=v6_ip,
            country=(primary.country if primary else None),
            # claude.ai's own view wins over any third-party geolocation.
            country_code=(
                (claude_trace.loc.upper() if claude_trace and claude_trace.ok and claude_trace.loc else None)
                or (primary.country_code if primary else None)
                or _trace_loc(trace_obs)
            ),
            city=primary.city if primary else None,
            asn=primary.asn if primary else None,
            org=primary.org if primary else None,
            colo=claude_trace.colo if claude_trace and claude_trace.ok else None,
            rpki=rpki_info.status if rpki_info and rpki_info.ok else None,
            asn_kind=primary.asn_kind if primary else None,
            timezone=local_info.timezone,
            locale=local_info.locale,
            languages=local_info.languages,
            browser=local_info.browsers[0] if local_info.browsers else None,
            os=local_info.os,
            fingerprint=local_info.machine_fingerprint,
            account_state=account_value,
        )

        sources = _dedupe_sources(
            [obs.source for obs in observations.values()]
            + [source for finding in findings for source in finding.sources]
            + ([account_state.source] if account_state and account_state.source else [])
        )

        for obs in observations.values():
            if obs.error:
                errors.append(f"{obs.key}: {obs.error}")

        report = Report(
            run_id=uuid.uuid4().hex[:12],
            started_at=started_at,
            finished_at=datetime.now(timezone.utc),
            app_version=__version__,
            rules_version=str(weights.get("version", 1)),
            verdict=verdict,
            score=report_score,
            level=report_level,
            coverage=coverage,
            confidence=confidence,
            score_basis=score_basis,
            categories=categories,
            findings=findings,
            observations=observations,
            environment=env,
            traces=traces,
            claude_egress=claude_trace,
            rpki=rpki_info,
            network_mode=network_mode,
            runtimes=runtime_probes,
            ip=primary,
            ipv4=ipv4,
            ipv6=ipv6,
            rdap=rdap_info,
            regions=regions,
            status=service,
            account=account_state,
            profile=profile,
            client=cc_info,
            local=local_info,
            browser=browser_probe,
            behavior=behavior_data,
            history=history,
            drift=drift,
            sources=sources,
            disclaimers=list(DISCLAIMERS),
            errors=errors,
        )
        store.save(report)
        return report
    finally:
        if own_http:
            client.close()
