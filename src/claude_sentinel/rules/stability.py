"""Egress stability: per-domain egress, churn, country jumps, dual-stack, drift."""

from __future__ import annotations

from claude_sentinel.models import (
    Category,
    FixType,
    Severity,
    Status,
    Visibility,
)
from claude_sentinel.rules.context import Context
from claude_sentinel.rules.registry import RuleMeta, RuleResult, rule
from claude_sentinel.rules.sources import IP_API, LOCAL, TRACE_CF, TRACE_CLAUDE


def _fmt_location(trace) -> str:
    parts = [trace.ip or "?", trace.loc or "?", f"colo={trace.colo or '?'}"]
    return " · ".join(parts)


@rule(
    RuleMeta(
        id="stability.egress_domain_mismatch",
        title="不同域名的出口不一致",
        category=Category.stability,
        severity=Severity.critical,
        max_points=45,
        fix=(
            "检查代理的分流规则：让 claude.ai、anthropic.com、api.anthropic.com 和你的终端走同一个出口。"
            "常见原因是只给部分域名配了规则，其他域名直连。"
        ),
        fix_type=FixType.network,
        visibility=Visibility.server,
        sources=[TRACE_CLAUDE, TRACE_CF],
        description=(
            "决定 Claude 看到什么的是 claude.ai 自己的出口，不是通用测速域名。"
            "两者不一致时，通用域名上的“干净”结论对 Claude 不成立。"
        ),
    )
)
def egress_domain_mismatch(ctx: Context) -> RuleResult | None:
    ok_traces = ctx.ok_traces
    if not ok_traces:
        return RuleResult(Status.unknown, "所有域名的边缘 trace 都不可达")

    countries = {trace.loc.upper() for trace in ok_traces if trace.loc}
    anchor = ctx.claude_egress
    if len(countries) > 1:
        detail = "；".join(f"{t.domain or t.key} → {t.loc}/{t.ip}" for t in ok_traces)
        return RuleResult(
            Status.high,
            f"不同域名的出口国家不一致：{detail}",
            details={
                "views": {t.key: _fmt_location(t) for t in ok_traces},
                "countries": sorted(countries),
            },
        )

    if len(ok_traces) < 2:
        return RuleResult(
            Status.warn,
            f"只探测到 {ok_traces[0].domain or ok_traces[0].key} 一个出口，无法交叉验证",
        )

    anchor_ip = anchor.ip if anchor else None
    if anchor_ip and all(trace.ip == anchor_ip for trace in ok_traces):
        return RuleResult(Status.ok, f"所有域名出口一致（{anchor.loc} · {anchor_ip}）")
    # Same country, different IPs: the domains are not taking one identical
    # path. Usually harmless (load-balanced proxy nodes), but worth knowing.
    spread = "；".join(f"{t.domain or t.key}={t.ip}" for t in ok_traces)
    return RuleResult(
        Status.warn,
        f"出口国家一致（{anchor.loc if anchor else '?'}），但各域名 IP 不同：{spread}",
    )


@rule(
    RuleMeta(
        id="stability.egress_unsupported",
        title="Claude 实际出口在不支持地区",
        category=Category.stability,
        severity=Severity.critical,
        max_points=50,
        fix=(
            "以 claude.ai 的出口为准整改：确认代理覆盖 claude.ai 与 api.anthropic.com，"
            "并检查 DNS 与 IPv6 是否绕过了代理。"
        ),
        fix_type=FixType.network,
        visibility=Visibility.server,
        sources=[TRACE_CLAUDE],
        description="通用探测域名可能落在支持地区，而 Claude 实际看到的是不支持地区。",
    )
)
def egress_unsupported(ctx: Context) -> RuleResult | None:
    country = ctx.claude_country
    trace = ctx.claude_egress
    if not country or trace is None:
        return RuleResult(Status.unknown, "所有域名的出口国家都未知")
    if not ctx.regions or not ctx.regions.codes:
        return RuleResult(Status.unknown, "官方支持地区列表不可用")

    # Say which domain answered, so a fallback view is never presented as
    # claude.ai's own answer.
    via = "" if ctx.claude_trace_is_direct else f"（claude.ai 不可达，依据 {trace.domain or trace.key}）"
    if country in ctx.regions.codes:
        return RuleResult(Status.ok, f"出口 {country} 在官方支持列表内{via}")
    if ctx.claude_trace_is_direct:
        return RuleResult(
            Status.high,
            f"claude.ai 实际出口国家 {country} 不在官方支持列表",
            details={"country": country},
        )
    return RuleResult(
        Status.warn,
        f"出口国家 {country} 不在官方支持列表{via}",
        details={"country": country},
    )


@rule(
    RuleMeta(
        id="stability.country_jump",
        title="短时间内跨国跳变",
        category=Category.stability,
        severity=Severity.critical,
        max_points=50,
        fix="固定一个出口地区；登录/使用期间不要在同一小时内跨国家切换节点。",
        fix_type=FixType.network,
        visibility=Visibility.server,
        sources=[IP_API],
    )
)
def country_jump(ctx: Context) -> RuleResult | None:
    if ctx.history.is_baseline:
        return None
    if ctx.history.country_jumps_1h > 0:
        return RuleResult(
            Status.high,
            f"最近 1 小时检测到 {ctx.history.country_jumps_1h} 次跨国跳变",
        )
    return RuleResult(Status.ok, "最近 1 小时没有跨国跳变")


@rule(
    RuleMeta(
        id="stability.ip_churn",
        title="出口 IP 变化频繁",
        category=Category.stability,
        severity=Severity.high,
        max_points=30,
        fix="固定出口；避免使用会频繁换 IP 的池化代理。",
        fix_type=FixType.network,
        visibility=Visibility.server,
        sources=[IP_API],
    )
)
def ip_churn(ctx: Context) -> RuleResult | None:
    if ctx.history.is_baseline:
        return None
    if ctx.history.distinct_ips_24h >= 4 or ctx.history.distinct_ips_7d >= 10:
        return RuleResult(
            Status.high,
            f"24h 内 {ctx.history.distinct_ips_24h} 个 IP，7d 内 {ctx.history.distinct_ips_7d} 个",
        )
    if ctx.history.distinct_ips_24h >= 2:
        return RuleResult(
            Status.warn,
            f"24h 内出现 {ctx.history.distinct_ips_24h} 个出口 IP",
        )
    return RuleResult(Status.ok, "近期出口 IP 稳定")


@rule(
    RuleMeta(
        id="stability.asn_churn",
        title="出口 ASN 变化频繁",
        category=Category.stability,
        severity=Severity.medium,
        max_points=20,
        fix="尽量保持同一运营商/ASN；频繁换 ASN 比换 IP 更容易被看出环境漂移。",
        fix_type=FixType.network,
        visibility=Visibility.server,
        sources=[IP_API],
    )
)
def asn_churn(ctx: Context) -> RuleResult | None:
    if ctx.history.is_baseline:
        return None
    if ctx.history.distinct_asns_24h >= 3:
        return RuleResult(
            Status.high,
            f"24h 内出现 {ctx.history.distinct_asns_24h} 个 ASN",
        )
    if ctx.history.distinct_asns_24h >= 2:
        return RuleResult(
            Status.warn,
            f"24h 内出现 {ctx.history.distinct_asns_24h} 个 ASN",
        )
    return RuleResult(Status.ok, "近期 ASN 稳定")


@rule(
    RuleMeta(
        id="stability.dual_stack",
        title="IPv4/IPv6 出口不一致",
        category=Category.stability,
        severity=Severity.high,
        max_points=40,
        fix="检查双栈分流；不要让 IPv6 绕过代理直连。Claude 可能看到与 IPv4 不同的 IPv6 出口。",
        fix_type=FixType.network,
        visibility=Visibility.server,
        sources=[IP_API],
    )
)
def dual_stack(ctx: Context) -> RuleResult | None:
    if not ctx.ipv4 or not ctx.ipv6:
        return RuleResult(Status.unknown, "缺少 IPv4 或 IPv6 出口数据")
    code4 = ctx.ipv4.country_code
    code6 = ctx.ipv6.country_code
    if not code4 or not code6:
        return RuleResult(Status.unknown, "双栈国家未知")
    if code4 != code6:
        return RuleResult(
            Status.high,
            f"IPv4 出口 {code4}，IPv6 出口 {code6}",
            details={"ipv4": code4, "ipv6": code6},
        )
    asn4 = (ctx.ipv4.asn or "").upper()
    asn6 = (ctx.ipv6.asn or "").upper()
    if asn4 and asn6 and asn4 != asn6:
        return RuleResult(
            Status.warn,
            f"双栈国家一致（{code4}），但 ASN 不同：{asn4} / {asn6}",
        )
    return RuleResult(Status.ok, f"双栈出口一致（{code4}）")


@rule(
    RuleMeta(
        id="stability.path_mismatch",
        title="主路径与双栈探测出口不一致",
        category=Category.stability,
        severity=Severity.high,
        max_points=30,
        fix="检查代理分流、DNS 和 IPv6 路由；让 Claude 实际请求路径与探测路径走同一个出口。",
        fix_type=FixType.network,
        visibility=Visibility.server,
        sources=[IP_API],
    )
)
def path_mismatch(ctx: Context) -> RuleResult | None:
    if not ctx.ip or not ctx.ip.country_code:
        return RuleResult(Status.unknown, "主路径出口国家未知")
    primary = ctx.ip.country_code
    mismatches = []
    for label, item in (("IPv4", ctx.ipv4), ("IPv6", ctx.ipv6)):
        if item and item.country_code and item.country_code != primary:
            mismatches.append(f"{label} {item.country_code}")
    if mismatches:
        return RuleResult(
            Status.high,
            f"主路径 {primary}，但 " + " / ".join(mismatches) + " 探测不一致",
        )
    if ctx.ipv4 or ctx.ipv6:
        return RuleResult(Status.ok, f"主路径与双栈探测一致（{primary}）")
    return RuleResult(Status.unknown, "缺少双栈探测数据")


@rule(
    RuleMeta(
        id="stability.browser_cli",
        title="浏览器与终端出口不一致",
        category=Category.stability,
        severity=Severity.high,
        max_points=30,
        fix="让浏览器和终端走同一路径；如果你用浏览器访问 Claude，以浏览器出口为准复测。",
        fix_type=FixType.network,
        visibility=Visibility.browser_js,
        sources=[LOCAL],
    )
)
def browser_cli(ctx: Context) -> RuleResult | None:
    if not ctx.browser or not ctx.browser.egress_ip:
        return None
    browser_code = ctx.browser_country
    code = ctx.country_code
    if not browser_code or not code:
        return RuleResult(Status.unknown, "浏览器或终端出口国家未知")
    if browser_code != code:
        return RuleResult(
            Status.high,
            f"浏览器出口 {browser_code}，终端出口 {code}",
            details={"browser_ip": ctx.browser.egress_ip, "cli_ip": ctx.ip.ip if ctx.ip else None},
        )
    return RuleResult(Status.ok, f"浏览器与终端出口一致（{code}）")


@rule(
    RuleMeta(
        id="stability.drift_country",
        title="与上次相比出口国家变化",
        category=Category.stability,
        severity=Severity.high,
        max_points=40,
        fix="如果这不是你有意的迁移，恢复上次的出口地区；频繁跨国变化是强信号。",
        fix_type=FixType.network,
        visibility=Visibility.server,
        sources=[LOCAL],
    )
)
def drift_country(ctx: Context) -> RuleResult | None:
    item = ctx.drift("country")
    if item is None:
        return None
    if item.changed:
        return RuleResult(Status.high, f"{item.previous or '?'} → {item.current or '?'}")
    return RuleResult(Status.ok, "出口国家未变")


@rule(
    RuleMeta(
        id="stability.drift_timezone",
        title="与上次相比系统时区变化",
        category=Category.stability,
        severity=Severity.medium,
        max_points=20,
        fix="保持系统时区稳定；不要为了配合节点频繁改时区。",
        fix_type=FixType.locale,
        visibility=Visibility.browser_js,
        sources=[LOCAL],
    )
)
def drift_timezone(ctx: Context) -> RuleResult | None:
    item = ctx.drift("timezone")
    if item is None:
        return None
    if item.changed:
        return RuleResult(Status.warn, f"{item.previous or '?'} → {item.current or '?'}")
    return RuleResult(Status.ok, "系统时区未变")


@rule(
    RuleMeta(
        id="stability.drift_ip",
        title="与上次相比出口 IP 变化",
        category=Category.stability,
        severity=Severity.low,
        max_points=10,
        fix="偶尔变化正常；短时间频繁变化需要固定出口。",
        fix_type=FixType.network,
        visibility=Visibility.server,
        sources=[LOCAL],
    )
)
def drift_ip(ctx: Context) -> RuleResult | None:
    item = ctx.drift("ip")
    if item is None:
        return None
    if item.changed:
        return RuleResult(Status.warn, "出口 IP 与上次不同")
    return RuleResult(Status.ok, "出口 IP 未变")


@rule(
    RuleMeta(
        id="stability.drift_fingerprint",
        title="与上次相比设备指纹变化",
        category=Category.stability,
        severity=Severity.low,
        max_points=15,
        fix="指纹变化可能来自系统更新或隐私插件；如果每次都变，检查浏览器指纹随机化扩展。",
        fix_type=FixType.none,
        visibility=Visibility.local,
        sources=[LOCAL],
    )
)
def drift_fingerprint(ctx: Context) -> RuleResult | None:
    item = ctx.drift("fingerprint")
    if item is None:
        return None
    if item.changed:
        return RuleResult(Status.warn, "设备指纹与上次不同")
    return RuleResult(Status.ok, "设备指纹未变")


@rule(
    RuleMeta(
        id="stability.baseline",
        title="历史基线",
        category=Category.stability,
        severity=Severity.info,
        max_points=0,
        fix="这是第一次记录；下次运行才能判断稳定性。",
        fix_type=FixType.none,
        visibility=Visibility.local,
        sources=[LOCAL],
    )
)
def baseline(ctx: Context) -> RuleResult | None:
    if ctx.history.is_baseline:
        return RuleResult(Status.info, "已记录首次基线")
    return None


@rule(
    RuleMeta(
        id="stability.proxy_mode_bypass",
        title="系统代理模式：终端与 Claude Code 可能绕过代理",
        category=Category.stability,
        severity=Severity.high,
        max_points=30,
        fix=(
            "系统代理只覆盖「会读系统代理设置」的应用。终端里的 curl/Node/Claude Code "
            "默认不读，会直连。要么开 TUN/增强模式接管全局，要么在终端显式设置 HTTPS_PROXY。"
        ),
        fix_type=FixType.network,
        visibility=Visibility.local,
        sources=[LOCAL],
        description=(
            "TUN 模式在路由层接管全部流量；系统代理模式只覆盖遵守代理设置的应用。"
            "两者的覆盖面差别很大。"
        ),
    )
)
def proxy_mode_bypass(ctx: Context) -> RuleResult | None:
    mode = ctx.network_mode
    if mode is None:
        return RuleResult(Status.unknown, "未检测到网络接管方式")
    if mode.tun_active:
        return RuleResult(Status.ok, f"TUN 模式已接管（{mode.tun_interface}）")
    if mode.system_proxy_enabled:
        host = f"{mode.system_proxy_host}:{mode.system_proxy_port}" if mode.system_proxy_host else "系统代理"
        return RuleResult(
            Status.warn,
            f"未启用 TUN，仅系统代理（{host}）；终端工具默认不走它",
            details={
                "tun": False,
                "proxy": host,
                "ipv4_interface": mode.ipv4_interface,
            },
        )
    return RuleResult(Status.warn, "未发现 TUN 或系统代理，当前为直连")


@rule(
    RuleMeta(
        id="stability.tun_not_dns",
        title="TUN 已开但 DNS 未走隧道",
        category=Category.stability,
        severity=Severity.medium,
        max_points=20,
        fix=(
            "TUN 模式下要同时接管 DNS（fake-ip 或远端解析）。"
            "若 DNS 仍填本地 ISP 服务器，解析请求依旧从本地出去。"
        ),
        fix_type=FixType.network,
        visibility=Visibility.local,
        sources=[LOCAL],
    )
)
def tun_not_dns(ctx: Context) -> RuleResult | None:
    """Is DNS actually captured by the tunnel?

    The configured nameserver says nothing: Clash-style TUN keeps a domestic
    resolver in ``resolv.conf`` and intercepts the queries anyway, answering
    with fake-ip addresses. The only real evidence is what the OS *resolves*
    to, so check the sampled answers rather than the nameserver list.
    """
    from claude_sentinel.rules.identity import dns_captured

    mode = ctx.network_mode
    if mode is None or not mode.tun_active:
        return None
    captured = dns_captured(ctx)
    if captured is True:
        return RuleResult(Status.ok, "DNS 已被 TUN 接管（解析结果为 fake-ip）")
    if captured is False:
        return RuleResult(
            Status.warn,
            "TUN 已开，但解析返回真实地址，说明 DNS 查询没走隧道",
        )
    if mode.local_resolvers:
        return RuleResult(
            Status.warn,
            f"TUN 已开，但无法确认 DNS 是否被接管（配置为 {'/'.join(mode.local_resolvers[:2])}）",
        )
    return RuleResult(Status.unknown, "未能读取系统 DNS 配置")


@rule(
    RuleMeta(
        id="stability.webrtc_leak",
        title="WebRTC 暴露了非代理出口",
        category=Category.stability,
        severity=Severity.high,
        max_points=25,
        fix=(
            "WebRTC 会绕过 HTTP 代理直连 STUN，把真实出口暴露给网页。"
            "在浏览器关闭 WebRTC（或强制走代理），再重新跑 sentinel probe。"
        ),
        fix_type=FixType.network,
        visibility=Visibility.browser_js,
        sources=[LOCAL],
    )
)
def webrtc_leak(ctx: Context) -> RuleResult | None:
    if not ctx.browser:
        return None
    leaked = ctx.webrtc_public_ips
    if not leaked:
        if ctx.browser.webrtc:
            return RuleResult(Status.ok, f"{len(ctx.browser.webrtc)} 个候选，未发现公网直连地址")
        return RuleResult(Status.unknown, "未采集到 WebRTC 候选")
    browser_ip = ctx.browser.egress_ip
    if browser_ip and all(ip == browser_ip for ip in leaked):
        return RuleResult(Status.ok, "WebRTC 出口与浏览器出口一致")
    return RuleResult(
        Status.high,
        f"WebRTC 直连暴露：{', '.join(leaked[:3])}（浏览器出口 {browser_ip or '未知'}）",
        details={"leaked": leaked, "browser_ip": browser_ip},
    )


@rule(
    RuleMeta(
        id="stability.runtime_split",
        title="Claude Code 运行时与浏览器走出不同国家",
        category=Category.stability,
        severity=Severity.critical,
        max_points=50,
        fix=(
            "Node 不读取 macOS 的「系统代理」，只认 HTTPS_PROXY 环境变量。"
            "在 shell 配置里 export HTTPS_PROXY/HTTP_PROXY 指向你的代理，"
            "或改用 TUN 模式在路由层接管。否则 Claude Code 是直连出去的。"
        ),
        fix_type=FixType.network,
        visibility=Visibility.server,
        sources=[TRACE_CLAUDE, LOCAL],
        description=(
            "浏览器遵守系统代理，Node（Claude Code 的运行时）不遵守。"
            "两者出口不同时，你在网页上看到的干净环境对 Claude Code 并不成立。"
        ),
    )
)
def runtime_split(ctx: Context) -> RuleResult | None:
    node = ctx.node_runtime
    if node is None or not node.loc:
        return RuleResult(Status.unknown, "未能从 Node 运行时测得出口")
    browser = ctx.claude_egress
    if browser is None or not browser.loc:
        return RuleResult(Status.unknown, "未能测得浏览器出口，无法对比")

    node_loc = node.loc.upper()
    web_loc = browser.loc.upper()
    if node_loc != web_loc:
        return RuleResult(
            Status.high,
            f"Claude Code（Node）出口 {node_loc}（{node.ip}），"
            f"但浏览器出口 {web_loc}（{browser.ip}）——终端没走代理",
            details={"node": node.ip, "browser": browser.ip},
        )
    if node.ip and browser.ip and node.ip != browser.ip:
        return RuleResult(
            Status.warn,
            f"国家一致（{node_loc}），但 Node 与浏览器 IP 不同：{node.ip} / {browser.ip}",
        )
    return RuleResult(Status.ok, f"Node 与浏览器出口一致（{node_loc}）")


@rule(
    RuleMeta(
        id="stability.runtime_no_proxy_env",
        title="终端未配置代理环境变量",
        category=Category.stability,
        severity=Severity.medium,
        max_points=20,
        fix=(
            "在 ~/.zshrc 里设置：export HTTPS_PROXY=http://127.0.0.1:7897 "
            "（端口按你的客户端改），并同时设置 HTTP_PROXY 与 ALL_PROXY。"
        ),
        fix_type=FixType.network,
        visibility=Visibility.local,
        sources=[LOCAL],
    )
)
def runtime_no_proxy_env(ctx: Context) -> RuleResult | None:
    mode = ctx.network_mode
    if mode is None:
        return None
    if mode.tun_active:
        # A TUN interface captures Node regardless of env vars.
        return RuleResult(Status.ok, "TUN 已接管，无需代理环境变量")
    if not mode.system_proxy_enabled:
        return None
    node = ctx.node_runtime
    if node is not None and node.proxies_env:
        return RuleResult(Status.ok, "终端已配置代理环境变量")
    return RuleResult(
        Status.warn,
        "系统代理已开，但终端没有 HTTPS_PROXY，Node/Claude Code 会直连",
    )
