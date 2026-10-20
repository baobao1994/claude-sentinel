"""Network mode (TUN vs system proxy), DNS leak and WebRTC leak rules."""

from __future__ import annotations

from pathlib import Path

import pytest

from claude_sentinel.collectors import netmode
from claude_sentinel.config import Settings
from claude_sentinel.models import (
    BrowserProbe,
    HistorySummary,
    IpConsensus,
    NetworkMode,
    RegionList,
    WebRtcCandidate,
)
from claude_sentinel.rules import evaluate
from claude_sentinel.rules.context import Context, GateInfo


def _ctx(**overrides) -> Context:
    base = dict(
        settings=Settings(home=Path("/tmp/unused")),
        observations={},
        ip=IpConsensus(ip="45.129.1.1", country_code="SG", country="Singapore"),
        ipv4=None,
        ipv6=None,
        rdap=None,
        regions=RegionList(codes={"SG", "US"}),
        status=None,
        account=None,
        profile=None,
        client=None,
        local=None,
        browser=None,
        behavior=None,
        history=HistorySummary(),
        gate=GateInfo(),
        traces=[],
        rpki=None,
        network_mode=None,
    )
    base.update(overrides)
    return Context(**base)


def _findings(ctx: Context) -> dict[str, object]:
    return {f.rule_id: f for f in evaluate(ctx)}


# ------------------------------------------------------------- collectors
def test_route_probe_reports_the_ipv4_default_interface(monkeypatch):
    monkeypatch.setattr(
        netmode,
        "_run",
        lambda argv, timeout=4.0: "   route to: default\ninterface: en0\n",
    )
    assert netmode.ipv4_default_interface() == "en0"


def test_tun_interface_is_only_reported_when_it_carries_the_default_route(monkeypatch):
    monkeypatch.setattr(
        netmode,
        "_run",
        lambda argv, timeout=4.0: "   route to: default\ninterface: utun4\n",
    )
    assert netmode.tun_interface() == "utun4"

    monkeypatch.setattr(
        netmode,
        "_run",
        lambda argv, timeout=4.0: "   route to: default\ninterface: en0\n",
    )
    # Idle utun devices exist on every modern macOS; they must not count.
    assert netmode.tun_interface() is None


def test_system_proxy_parsing(monkeypatch):
    payload = """
<dictionary> {
  HTTPEnable : 1
  HTTPPort : 7897
  HTTPProxy : 127.0.0.1
  HTTPSEnable : 1
  SOCKSEnable : 1
  ProxyAutoConfigEnable : 0
}
"""
    monkeypatch.setattr(netmode, "_run", lambda argv, timeout=4.0: payload)
    info = netmode.system_proxy()
    assert info["enabled"] is True
    assert info["host"] == "127.0.0.1"
    assert info["port"] == 7897


def test_system_proxy_disabled(monkeypatch):
    monkeypatch.setattr(
        netmode,
        "_run",
        lambda argv, timeout=4.0: "<dictionary> {\n  HTTPEnable : 0\n  ProxyAutoConfigEnable : 0\n}\n",
    )
    info = netmode.system_proxy()
    assert info["enabled"] is False


def test_resolvers_are_parsed_from_scutil(monkeypatch):
    payload = """
resolver #1
  nameserver[0] : 114.114.114.114
  nameserver[1] : 223.5.5.5
resolver #2
  nameserver[0] : 114.114.114.114
"""
    monkeypatch.setattr(netmode, "_run", lambda argv, timeout=4.0: payload)
    assert netmode.local_resolvers() == ["114.114.114.114", "223.5.5.5"]


def test_collect_reports_proxy_mode_and_resolvers(monkeypatch):
    def fake_run(argv, timeout=4.0):
        if argv[:2] == ["route", "-n"]:
            return "interface: en0\n"
        if argv[:2] == ["scutil", "--proxy"]:
            return "HTTPEnable : 1\nHTTPProxy : 127.0.0.1\nHTTPPort : 7897\n"
        if argv[:2] == ["scutil", "--dns"]:
            return "nameserver[0] : 114.114.114.114\n"
        return None

    monkeypatch.setattr(netmode, "_run", fake_run)
    mode, observations = netmode.collect_network_mode()
    assert mode.summary == "系统代理"
    assert mode.tun_active is False
    assert mode.local_resolvers == ["114.114.114.114"]
    assert {o.key for o in observations} == {"net.mode", "net.resolvers", "net.dns_resolution"}


def test_collect_reports_tun_when_it_carries_the_route(monkeypatch):
    def fake_run(argv, timeout=4.0):
        if argv[:2] == ["route", "-n"]:
            return "interface: utun3\n"
        return ""

    monkeypatch.setattr(netmode, "_run", fake_run)
    mode, _ = netmode.collect_network_mode()
    assert mode.tun_active is True
    assert mode.tun_interface == "utun3"
    assert mode.summary.startswith("TUN")


# ---------------------------------------------------------- proxy mode rule
def test_system_proxy_mode_is_flagged_as_terminal_bypass():
    mode = NetworkMode(ipv4_interface="en0", system_proxy_enabled=True, system_proxy_host="127.0.0.1", system_proxy_port=7897)
    finding = _findings(_ctx(network_mode=mode))["stability.proxy_mode_bypass"]
    assert finding.status == "warn"
    assert "系统代理" in finding.evidence


def test_tun_mode_passes():
    mode = NetworkMode(ipv4_interface="utun3", tun_interface="utun3", tun_active=True)
    finding = _findings(_ctx(network_mode=mode))["stability.proxy_mode_bypass"]
    assert finding.status == "ok"


def test_no_proxy_at_all_is_a_warning_not_a_pass():
    finding = _findings(_ctx(network_mode=NetworkMode()))["stability.proxy_mode_bypass"]
    assert finding.status == "warn"
    assert "直连" in finding.evidence


# -------------------------------------------------------------- DNS leak
def test_dns_leak_fires_when_egress_is_abroad_but_resolvers_are_domestic():
    mode = NetworkMode(local_resolvers=["114.114.114.114", "223.5.5.5"])
    finding = _findings(_ctx(network_mode=mode))["identity.dns_leak"]
    assert finding.status == "high"
    assert "114.114" in finding.evidence


def test_dns_leak_quiet_for_non_cn_resolvers():
    mode = NetworkMode(local_resolvers=["1.1.1.1", "8.8.8.8"])
    finding = _findings(_ctx(network_mode=mode))["identity.dns_leak"]
    assert finding.status == "ok"


def test_dns_leak_does_not_fire_when_egress_is_itself_cn():
    mode = NetworkMode(local_resolvers=["114.114.114.114"])
    ctx = _ctx(
        network_mode=mode,
        ip=IpConsensus(ip="203.0.113.250", country_code="CN", country="China"),
    )
    finding = _findings(ctx)["identity.dns_leak"]
    assert finding.status == "ok"


def test_dns_leak_unknown_without_resolvers():
    finding = _findings(_ctx(network_mode=NetworkMode()))["identity.dns_leak"]
    assert finding.status == "unknown"


def test_dns_leak_uses_the_ecs_probe_when_it_matches():
    from claude_sentinel.models import Observation, Source

    obs = Observation(
        key="net.dns",
        label="DNS 解析器",
        value={"ip": "114.114.114.2", "geo": "China - Chinanet"},
        source=Source(name="edns", kind="third_party"),
    )
    mode = NetworkMode(local_resolvers=["114.114.114.2"])
    finding = _findings(_ctx(network_mode=mode, observations={"net.dns": obs}))["identity.dns_leak"]
    assert finding.status == "high"


# --------------------------------------------------------------- TUN + DNS
def test_tun_without_dns_capture_is_flagged():
    mode = NetworkMode(tun_interface="utun3", tun_active=True, local_resolvers=["114.114.114.114"])
    finding = _findings(_ctx(network_mode=mode))["stability.tun_not_dns"]
    assert finding.status == "warn"


def test_fake_ip_range_counts_as_captured_dns():
    """A 198.18.x.x *resolution* means captured; the resolver list alone does not."""
    from claude_sentinel.models import Observation, Source

    mode = NetworkMode(tun_interface="utun3", tun_active=True, local_resolvers=["223.6.6.6"])
    obs = Observation(
        key="net.dns_resolution",
        label="DNS 解析结果",
        value={"answers": ["198.18.0.2"]},
        source=Source(name="local", kind="local"),
    )
    finding = _findings(_ctx(network_mode=mode, observations={"net.dns_resolution": obs}))[
        "stability.tun_not_dns"
    ]
    assert finding.status == "ok"


# ---------------------------------------------------------------- WebRTC
def _browser(candidates, egress_ip="45.129.1.1") -> BrowserProbe:
    return BrowserProbe(
        webrtc=[WebRtcCandidate(candidate=f"candidate:{i} typ {k}", ip=ip, kind=k) for i, (ip, k) in enumerate(candidates)],
        egress_ip=egress_ip,
        egress_country="SG",
    )


def test_webrtc_public_ip_that_differs_from_egress_is_a_leak():
    browser = _browser([("192.168.1.5", "host"), ("93.184.216.34", "srflx")])
    finding = _findings(_ctx(browser=browser))["stability.webrtc_leak"]
    assert finding.status == "high"
    assert "93.184.216.34" in finding.evidence


def test_webrtc_matching_egress_is_fine():
    browser = _browser([("45.129.1.1", "srflx")])
    finding = _findings(_ctx(browser=browser))["stability.webrtc_leak"]
    assert finding.status == "ok"


def test_webrtc_only_private_candidates_is_fine():
    browser = _browser([("192.168.1.5", "host"), ("10.0.0.7", "host")])
    finding = _findings(_ctx(browser=browser))["stability.webrtc_leak"]
    assert finding.status == "ok"


def test_webrtc_rule_is_silent_without_a_probe():
    assert "stability.webrtc_leak" not in _findings(_ctx())


def test_webrtc_unknown_when_no_candidates_were_collected():
    finding = _findings(_ctx(browser=BrowserProbe()))["stability.webrtc_leak"]
    assert finding.status == "unknown"


# ------------------------------------------------------------- cache race
def test_parallel_cache_writes_do_not_collide(tmp_path: Path):
    """The primary/v4/v6 IP lookups run in parallel and used to share one .tmp."""
    import threading

    from claude_sentinel.collectors.base import cache_read, cache_write

    errors: list[Exception] = []

    def writer(value: int) -> None:
        try:
            for _ in range(20):
                cache_write(tmp_path, f"key-{value}", {"value": value})
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert not errors
    for i in range(6):
        assert cache_read(tmp_path, f"key-{i}")["value"] == i
    assert not list(tmp_path.glob("*.tmp"))


@pytest.mark.parametrize("resolver", ["114.114.114.114", "223.5.5.5", "119.29.29.29", "180.76.76.76"])
def test_known_public_cn_resolvers_are_recognised(resolver: str):
    finding = _findings(_ctx(network_mode=NetworkMode(local_resolvers=[resolver])))["identity.dns_leak"]
    assert finding.status == "high"


# ------------------------------------------------- TUN detection under /1 split
def test_tun_is_detected_even_when_default_route_is_unchanged(monkeypatch):
    """Clash captures traffic with 0.0.0.0/1 + 128.0.0.0/1, not by replacing
    the default route. Reading `route get default` alone misses it entirely."""

    def fake_run(argv, timeout=4.0):
        if argv[:3] == ["route", "-n", "get"]:
            dest = argv[3]
            if dest == "default":
                return "   gateway: 192.168.1.1\n interface: en0\n"
            return "   gateway: 198.18.0.1\n interface: utun1024\n"
        return ""

    monkeypatch.setattr(netmode, "_run", fake_run)
    assert netmode.tun_interface() == "utun1024"
    assert netmode.physical_interface() == "en0"

    mode, _ = netmode.collect_network_mode()
    assert mode.tun_active is True
    assert mode.summary == "TUN (utun1024)"
    # The physical link is still reported, it just is not the egress any more.
    assert mode.ipv4_interface == "en0"


def test_no_tun_when_external_routes_go_out_the_physical_link(monkeypatch):
    monkeypatch.setattr(
        netmode,
        "_run",
        lambda argv, timeout=4.0: "   gateway: 192.168.1.1\n interface: en0\n",
    )
    assert netmode.tun_interface() is None
    assert netmode.physical_interface() == "en0"


# ------------------------------------------------------ fake-ip capture check
def _dns_obs(answers):
    from claude_sentinel.models import Observation, Source

    return Observation(
        key="net.dns_resolution",
        label="DNS 解析结果",
        value={"answers": answers},
        source=Source(name="local", kind="local"),
    )


def test_fake_ip_answers_prove_dns_is_captured():
    from claude_sentinel.rules.identity import dns_captured

    ctx = _ctx(observations={"net.dns_resolution": _dns_obs(["198.18.0.4"])})
    assert dns_captured(ctx) is True


def test_real_answers_prove_dns_is_not_captured():
    from claude_sentinel.rules.identity import dns_captured

    ctx = _ctx(observations={"net.dns_resolution": _dns_obs(["160.79.104.10"])})
    assert dns_captured(ctx) is False


def test_capture_is_unknown_without_samples():
    from claude_sentinel.rules.identity import dns_captured

    assert dns_captured(_ctx()) is None
    assert dns_captured(_ctx(observations={"net.dns_resolution": _dns_obs([])})) is None


def test_cn_nameserver_with_fake_ip_is_not_a_leak():
    """The exact situation on a TUN box: nameserver stays 223.6.6.6."""
    mode = NetworkMode(
        tun_interface="utun1024",
        tun_active=True,
        local_resolvers=["223.6.6.6"],
    )
    ctx = _ctx(
        network_mode=mode,
        observations={"net.dns_resolution": _dns_obs(["198.18.0.4", "198.18.0.12"])},
    )
    findings = _findings(ctx)
    assert findings["identity.dns_leak"].status == "ok"
    assert findings["stability.tun_not_dns"].status == "ok"


def test_tun_with_real_answers_is_flagged():
    mode = NetworkMode(
        tun_interface="utun1024",
        tun_active=True,
        local_resolvers=["223.6.6.6"],
    )
    ctx = _ctx(
        network_mode=mode,
        observations={"net.dns_resolution": _dns_obs(["160.79.104.10"])},
    )
    finding = _findings(ctx)["stability.tun_not_dns"]
    assert finding.status == "warn"
    assert "没走隧道" in finding.evidence


def test_fake_ip_membership_uses_containment_not_equality():
    """Regression: `addr in [network]` compares equality and silently fails."""
    import ipaddress

    from claude_sentinel.rules.identity import FAKE_IP_RANGES

    addr = ipaddress.ip_address("198.18.0.4")
    assert addr not in FAKE_IP_RANGES  # the trap
    assert any(addr in network for network in FAKE_IP_RANGES)
