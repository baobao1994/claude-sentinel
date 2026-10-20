"""How traffic actually leaves this machine: TUN device, system proxy, or direct.

"代理开着" and "代理生效" are different things. Clash/Surge style tools run in
either system-proxy mode (only apps that honour the proxy are covered) or TUN
mode (a virtual interface captures everything). A terminal tool that ignores
``HTTPS_PROXY`` will bypass system-proxy mode entirely, so the shell and
Claude Code can leave through a completely different path than the browser.

All checks here are read-only and local (``scutil``/``route``/``netstat``).
"""

from __future__ import annotations

import platform
import re
import subprocess

from claude_sentinel.models import (
    Confidence,
    NetworkMode,
    Observation,
    Source,
    SourceKind,
    Status,
)

SOURCE = Source(
    name="Local routing table / system proxy",
    kind=SourceKind.local,
    confidence=Confidence.high,
)

TUN_PREFIXES = ("utun", "tun", "tap", "wg", "ppp")


def _run(argv: list[str], timeout: float = 4.0) -> str | None:
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout


def ipv4_default_interface() -> str | None:
    """The interface carrying the IPv4 default route."""
    out = _run(["route", "-n", "get", "default"])
    if out:
        match = re.search(r"^\s*interface:\s*(\S+)", out, re.MULTILINE)
        if match:
            return match.group(1)
    # Linux fallback.
    out = _run(["ip", "route", "show", "default"])
    if out:
        match = re.search(r"default\s+.*?\bdev\s+(\S+)", out)
        if match:
            return match.group(1)
    return None


def ipv6_default_interface() -> str | None:
    out = _run(["route", "-n", "get", "-inet6", "default"])
    if out:
        match = re.search(r"^\s*interface:\s*(\S+)", out, re.MULTILINE)
        if match:
            return match.group(1)
    return None


def _interfaces() -> set[str]:
    if platform.system() == "Darwin":
        out = _run(["ifconfig", "-l"]) or ""
    else:
        out = _run(["ip", "-o", "link", "show"]) or ""
        return set(re.findall(r"\d+:\s+([^:@]+)", out))
    return set(out.split())


#: Public destinations used to ask "where does ordinary internet traffic go?".
#: Clash/Surge-style TUN devices commonly capture traffic with two /1 routes
#: (0.0.0.0/1 + 128.0.0.0/1) instead of replacing the default route, so reading
#: ``route get default`` still reports the physical interface. Probing a real
#: external address is the only reliable answer.
ROUTE_PROBES = ("1.1.1.1", "8.8.8.8")


def interface_for(destination: str) -> str | None:
    """Which interface macOS would use to reach ``destination``."""
    out = _run(["route", "-n", "get", destination])
    if out:
        match = re.search(r"^\s*interface:\s*(\S+)", out, re.MULTILINE)
        if match:
            return match.group(1)
    return None


def tun_interface() -> str | None:
    """A TUN-style interface that internet traffic actually goes through."""
    for destination in ROUTE_PROBES:
        iface = interface_for(destination)
        if iface and iface.startswith(TUN_PREFIXES):
            return iface
    # IPv6 fallback: some setups only capture v6.
    v6 = ipv6_default_interface()
    if v6 and v6.startswith(TUN_PREFIXES):
        return v6
    return None


def physical_interface() -> str | None:
    """The non-TUN interface that carried traffic before the tunnel.

    ``route get default`` still points at the physical link under a /1-split
    TUN, which is exactly what we want to report alongside the tunnel name.
    """
    default = ipv4_default_interface()
    if default and not default.startswith(TUN_PREFIXES):
        return default
    for destination in ROUTE_PROBES:
        iface = interface_for(destination)
        if iface and not iface.startswith(TUN_PREFIXES):
            return iface
    return default


def system_proxy() -> dict[str, object]:
    """System proxy settings (macOS ``scutil --proxy``)."""
    out = _run(["scutil", "--proxy"])
    if not out:
        return {"enabled": False, "details": None, "host": None, "port": None}
    enabled = []
    host = None
    port = None
    for line in out.splitlines():
        line = line.strip()
        parts = line.split(":", 1)
        if len(parts) != 2:
            continue
        key, value = parts[0].strip(), parts[1].strip()
        if key in {"HTTPEnable", "HTTPSEnable", "SOCKSEnable", "ProxyAutoConfigEnable"} and value == "1":
            enabled.append(key)
        if key in {"HTTPSProxy", "HTTPProxy", "SOCKSProxy"} and host is None:
            host = value
        if key in {"HTTPSPort", "HTTPPort", "SOCKSPort"} and port is None:
            try:
                port = int(value)
            except ValueError:
                port = None
    return {
        "enabled": bool(enabled),
        "details": ", ".join(enabled) if enabled else None,
        "host": host,
        "port": port,
    }


def local_resolvers() -> list[str]:
    """The DNS servers the OS is configured to use."""
    if platform.system() == "Darwin":
        out = _run(["scutil", "--dns"]) or ""
        return sorted(set(re.findall(r"nameserver\[\d+\]\s*:\s*(\S+)", out)))
    out = _run(["cat", "/etc/resolv.conf"]) or ""
    return sorted(set(re.findall(r"^nameserver\s+(\S+)", out, re.MULTILINE)))


def collect_network_mode() -> tuple[NetworkMode, list[Observation]]:
    tun = tun_interface()
    proxy = system_proxy()
    v4 = physical_interface()
    resolvers = local_resolvers()

    mode = NetworkMode(
        ipv4_interface=v4,
        ipv6_interface=ipv6_default_interface(),
        tun_interface=tun,
        tun_active=tun is not None,
        system_proxy_enabled=bool(proxy["enabled"]),
        system_proxy_host=proxy["host"] if isinstance(proxy["host"], str) else None,
        system_proxy_port=proxy["port"] if isinstance(proxy["port"], int) else None,
        local_resolvers=resolvers,
    )

    if tun:
        detail = f"TUN 模式：{tun}"
        status = Status.ok
    elif proxy["enabled"]:
        detail = f"系统代理模式：{proxy['host'] or '?'}:{proxy['port'] or '?'}"
        status = Status.info
    else:
        detail = "直连（未发现 TUN 或系统代理）"
        status = Status.info

    observations = [
        collect_dns_resolution(),
        Observation(
            key="net.mode",
            label="网络接管方式",
            value={
                "mode": mode.summary,
                "tun": tun,
                "proxy": proxy.get("details"),
                "ipv4_interface": v4,
            },
            status=status,
            source=SOURCE,
            visibility="local",
            detail=detail,
        ),
        Observation(
            key="net.resolvers",
            label="系统 DNS 解析器",
            value={"resolvers": resolvers},
            status=Status.ok if resolvers else Status.unknown,
            source=SOURCE,
            visibility="local",
            detail=(
                f"系统配置 {len(resolvers)} 个解析器"
                if resolvers
                else "未能读取系统 DNS 配置"
            ),
        ),
    ]
    return mode, observations

#: Hostnames whose resolution tells us whether DNS is intercepted by a TUN.
RESOLUTION_PROBES = ("claude.ai", "www.anthropic.com")


def resolve_probe(host: str) -> list[str]:
    """Resolve via the OS resolver -- exactly what an app would get."""
    try:
        import socket

        infos = socket.getaddrinfo(host, 443, socket.AF_INET)
    except OSError:
        return []
    answers: list[str] = []
    for info in infos:
        address = info[4][0]
        if isinstance(address, str) and address not in answers:
            answers.append(address)
    return answers


def collect_dns_resolution() -> Observation:
    """Does the OS get a fake-ip (captured) or a real address (leaked)?"""
    samples: dict[str, list[str]] = {}
    for host in RESOLUTION_PROBES:
        answers = resolve_probe(host)
        if answers:
            samples[host] = answers
    return Observation(
        key="net.dns_resolution",
        label="DNS 解析结果",
        value={"answers": [ip for answers in samples.values() for ip in answers], "samples": samples},
        status=Status.ok if samples else Status.unknown,
        source=SOURCE,
        visibility="local",
        detail=(
            "解析结果已采样"
            if samples
            else "无法通过系统解析器获取结果"
        ),
    )
