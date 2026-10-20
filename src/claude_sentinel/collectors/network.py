"""Network path collectors: per-domain edge view, dual-stack, DNS.

The important detail is *per domain*. Proxy rules are usually written per
hostname, so ``www.cloudflare.com`` (a convenient probe) and ``claude.ai``
(what actually matters) may leave through completely different IPs. Measuring
only the generic domain can therefore report "clean" while Claude sees a
different egress entirely.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from typing import Any

from claude_sentinel.collectors.base import Http, source_from_response
from claude_sentinel.models import (
    Confidence,
    EdgeTrace,
    Observation,
    Source,
    SourceKind,
    Status,
)

CF_TRACE = "https://www.cloudflare.com/cdn-cgi/trace"
EDNS = "https://edns.ip-api.com/json"

# Ordered by how much the result matters. ``claude.ai`` first: it is the path
# every browser session and API call actually takes.
TRACE_TARGETS: tuple[tuple[str, str, str], ...] = (
    ("trace.claude", "claude.ai", "https://claude.ai/cdn-cgi/trace"),
    ("trace.anthropic", "anthropic.com", "https://www.anthropic.com/cdn-cgi/trace"),
    ("trace.api", "api.anthropic.com", "https://api.anthropic.com/cdn-cgi/trace"),
    ("trace.cf", "cloudflare.com", CF_TRACE),
)

#: The probe whose answer drives the verdict: Claude's own hostname.
PRIMARY_TRACE_KEY = "trace.claude"


def _parse_trace(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            out[key.strip()] = value.strip()
    return out


def _trace_url(key: str) -> str:
    for target_key, _label, url in TRACE_TARGETS:
        if target_key == key:
            return url
    return CF_TRACE


def collect_cloudflare_trace(http: Http, key: str = "trace.cf") -> Observation:
    """Probe one Cloudflare trace endpoint.

    ``key`` selects the domain: ``trace.claude`` is the authoritative one for
    "what does Claude see", ``trace.cf`` is the generic control probe.
    """
    label, url = "Cloudflare 边缘视角", _trace_url(key)
    domain = ""
    for target_key, target_label, target_url in TRACE_TARGETS:
        if target_key == key:
            label, url, domain = f"{target_label} 出口", target_url, target_label
            break
    source = Source(
        name=f"{domain or 'Cloudflare'} /cdn-cgi/trace",
        kind=SourceKind.edge,
        url=url,
        confidence=Confidence.high,
    )
    started = time.monotonic()
    try:
        resp = http.fetch(url, follow_redirects=True)
        resp.raise_for_status()
        trace = _parse_trace(resp.text)
    except Exception as exc:  # noqa: BLE001
        latency = int((time.monotonic() - started) * 1000)
        return Observation(
            key=key,
            label=label,
            value=None,
            status=Status.unknown,
            source=source,
            visibility="server",
            detail=f"{domain or url} 不可达",
            error=str(exc),
            latency_ms=latency,
        )
    latency = int((time.monotonic() - started) * 1000)
    ip = trace.get("ip")
    loc = trace.get("loc")
    colo = trace.get("colo")
    value = {
        "domain": domain,
        "ip": ip,
        "loc": loc,
        "colo": colo,
        "warp": trace.get("warp"),
        "tls": trace.get("tls"),
        "http": trace.get("http"),
        "sni": trace.get("sni"),
    }
    return Observation(
        key=key,
        label=label,
        value=value,
        status=Status.ok if ip else Status.warn,
        source=source_from_response(f"{domain or 'Cloudflare'} trace", SourceKind.edge, url, resp),
        visibility="server",
        detail=f"{ip or '?'} · {loc or '?'} · colo={colo or '?'}",
        latency_ms=latency,
    )


def collect_traces(http: Http, retries: int = 1) -> list[Observation]:
    """Probe every relevant domain; never let one failure hide the others.

    A single dropped TLS handshake is common behind a busy proxy, so a failed
    probe is retried once before being reported as unreachable.
    """
    observations: list[Observation] = []
    for key, _label, _url in TRACE_TARGETS:
        observation = collect_cloudflare_trace(http, key)
        for _ in range(retries):
            if observation.status == Status.ok:
                break
            observation = collect_cloudflare_trace(http, key)
        observations.append(observation)
    return observations


def trace_model(observation: Observation) -> EdgeTrace:
    value = observation.value if isinstance(observation.value, dict) else {}
    return EdgeTrace(
        key=observation.key,
        label=observation.label,
        url=observation.source.url or "",
        domain=str(value.get("domain") or ""),
        ok=observation.status == Status.ok and bool(value.get("ip")),
        ip=value.get("ip"),
        loc=value.get("loc"),
        colo=value.get("colo"),
        warp=value.get("warp"),
        http=value.get("http"),
        tls=value.get("tls"),
        error=observation.error,
        latency_ms=observation.latency_ms,
    )



def _curl_trace(family: str, proxy: str | None = None) -> dict[str, Any] | None:
    curl = shutil.which("curl")
    if not curl:
        return None
    flag = "-4" if family == "v4" else "-6"
    env = os.environ.copy()
    if proxy:
        for key in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
            env[key] = proxy
    try:
        proc = subprocess.run(
            [curl, flag, "-sS", "--max-time", "6", CF_TRACE],
            capture_output=True,
            text=True,
            timeout=9,
            env=env,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0 or not proc.stdout:
        return None
    trace = _parse_trace(proc.stdout)
    if not trace.get("ip"):
        return None
    return {
        "ip": trace.get("ip"),
        "loc": trace.get("loc"),
        "colo": trace.get("colo"),
        "warp": trace.get("warp"),
    }


def collect_dual_stack(proxy: str | None = None) -> list[Observation]:
    observations: list[Observation] = []
    for family, label in (("v4", "IPv4 出口"), ("v6", "IPv6 出口")):
        data = _curl_trace(family, proxy)
        key = f"net.{family}"
        if data is None:
            observations.append(
                Observation(
                    key=key,
                    label=label,
                    value=None,
                    status=Status.skipped,
                    source=Source(
                        name=f"curl -{family[1]}",
                        kind=SourceKind.local,
                        url=CF_TRACE,
                        confidence=Confidence.medium,
                    ),
                    visibility="server",
                    detail="无 curl 或该协议不可达",
                )
            )
        else:
            observations.append(
                Observation(
                    key=key,
                    label=label,
                    value=data,
                    status=Status.ok,
                    source=Source(
                        name=f"curl -{family[1]} trace",
                        kind=SourceKind.edge,
                        url=CF_TRACE,
                        confidence=Confidence.high,
                    ),
                    visibility="server",
                    detail=f"{data.get('ip')} · {data.get('loc')} · colo={data.get('colo')}",
                )
            )
    return observations


def collect_dns(http: Http) -> Observation:
    source = Source(
        name="edns.ip-api.com",
        kind=SourceKind.third_party,
        url=EDNS,
        confidence=Confidence.medium,
    )
    try:
        resp = http.fetch(EDNS, follow_redirects=True)
        resp.raise_for_status()
        data = resp.json()
        dns = data.get("dns") or {}
        ip = dns.get("ip")
        geo = dns.get("geo")
    except Exception as exc:  # noqa: BLE001
        return Observation(
            key="net.dns",
            label="DNS 解析器",
            value=None,
            status=Status.unknown,
            source=source,
            visibility="server",
            detail="DNS 解析器信息不可达",
            error=str(exc),
        )
    return Observation(
        key="net.dns",
        label="DNS 解析器",
        value={"ip": ip, "geo": geo},
        status=Status.ok if ip else Status.warn,
        source=source_from_response("edns.ip-api.com", SourceKind.third_party, EDNS, resp),
        visibility="server",
        detail=f"{ip or '?'} · {geo or '?'}",
    )


def edge_ip(observation: Observation | None) -> str | None:
    if not observation or not isinstance(observation.value, dict):
        return None
    value = observation.value.get("ip")
    return value if isinstance(value, str) else None
