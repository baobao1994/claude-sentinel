"""Per-runtime egress: Node (Claude Code) vs the browser behind a system proxy."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from claude_sentinel.collectors import runtimes
from claude_sentinel.config import Settings
from claude_sentinel.models import (
    EdgeTrace,
    HistorySummary,
    IpConsensus,
    NetworkMode,
    RegionList,
    RuntimeProbe,
)
from claude_sentinel.rules import evaluate
from claude_sentinel.rules.context import Context, GateInfo


def _ctx(**overrides) -> Context:
    base = dict(
        settings=Settings(home=Path("/tmp/unused")),
        observations={},
        ip=IpConsensus(ip="45.129.1.1", country_code="SG"),
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
        traces=[EdgeTrace(key="trace.claude", label="claude.ai 出口", url="u", domain="claude.ai", ok=True, ip="45.129.1.1", loc="SG")],
        rpki=None,
        network_mode=NetworkMode(system_proxy_enabled=True, system_proxy_host="127.0.0.1", system_proxy_port=7897),
        runtimes=[],
    )
    base.update(overrides)
    return Context(**base)


def _findings(ctx: Context) -> dict[str, object]:
    return {f.rule_id: f for f in evaluate(ctx)}


def _node(ip: str, loc: str, proxies_env: bool = False) -> RuntimeProbe:
    return RuntimeProbe(
        runtime="node",
        label="Node / Claude Code",
        available=True,
        ok=True,
        ip=ip,
        loc=loc,
        proxies_env=proxies_env,
    )


# ------------------------------------------------------------- the real bug
def test_node_and_browser_on_different_countries_is_critical():
    """This is the exact situation the external review described."""
    ctx = _ctx(runtimes=[_node("203.0.113.250", "CN")])
    finding = _findings(ctx)["stability.runtime_split"]
    assert finding.status == "high"
    assert finding.points > 0
    assert "CN" in finding.evidence and "SG" in finding.evidence
    assert "终端没走代理" in finding.evidence


def test_same_country_different_ip_is_a_soft_warning():
    ctx = _ctx(runtimes=[_node("45.129.9.9", "SG")])
    finding = _findings(ctx)["stability.runtime_split"]
    assert finding.status == "warn"


def test_matching_node_and_browser_pass():
    ctx = _ctx(runtimes=[_node("45.129.1.1", "SG")])
    finding = _findings(ctx)["stability.runtime_split"]
    assert finding.status == "ok"


def test_runtime_split_unknown_without_node_probe():
    finding = _findings(_ctx(runtimes=[]))["stability.runtime_split"]
    assert finding.status == "unknown"


def test_runtime_split_unknown_when_node_probe_failed():
    failed = RuntimeProbe(runtime="node", label="Node", available=True, ok=False, error="ECONNREFUSED")
    finding = _findings(_ctx(runtimes=[failed]))["stability.runtime_split"]
    assert finding.status == "unknown"


# ------------------------------------------------------------ proxy env hint
def test_system_proxy_without_env_vars_is_flagged():
    ctx = _ctx(runtimes=[_node("203.0.113.250", "CN", proxies_env=False)])
    finding = _findings(ctx)["stability.runtime_no_proxy_env"]
    assert finding.status == "warn"
    assert "HTTPS_PROXY" in finding.evidence


def test_env_vars_present_passes():
    ctx = _ctx(runtimes=[_node("45.129.1.1", "SG", proxies_env=True)])
    finding = _findings(ctx)["stability.runtime_no_proxy_env"]
    assert finding.status == "ok"


def test_tun_mode_makes_env_vars_irrelevant():
    ctx = _ctx(
        network_mode=NetworkMode(tun_interface="utun3", tun_active=True),
        runtimes=[_node("45.129.1.1", "SG", proxies_env=False)],
    )
    finding = _findings(ctx)["stability.runtime_no_proxy_env"]
    assert finding.status == "ok"


def test_no_proxy_at_all_is_out_of_scope_for_this_rule():
    ctx = _ctx(network_mode=NetworkMode(), runtimes=[_node("203.0.113.250", "CN")])
    assert "stability.runtime_no_proxy_env" not in _findings(ctx)


# --------------------------------------------------------------- collectors
def test_node_probe_parses_trace(monkeypatch):
    monkeypatch.setattr(runtimes.shutil, "which", lambda name: "/usr/bin/node" if name == "node" else None)

    class Proc:
        returncode = 0
        stdout = json.dumps({"ok": True, "ip": "203.0.113.250", "loc": "CN", "colo": "LAX"})
        stderr = ""

    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["env"] = kwargs.get("env", {})
        return Proc()

    monkeypatch.setattr(runtimes.subprocess, "run", fake_run)
    probe = runtimes.probe_node()
    assert probe.ok and probe.ip == "203.0.113.250" and probe.loc == "CN"
    # Must run a real script file, not inline -e code.
    assert captured["argv"][1].endswith(".cjs")
    # And must strip proxy env vars so it measures the raw runtime path.
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        assert key not in captured["env"]


def test_node_probe_reports_missing_binary(monkeypatch):
    monkeypatch.setattr(runtimes.shutil, "which", lambda name: None)
    probe = runtimes.probe_node()
    assert probe.available is False
    assert probe.error


def test_node_probe_reports_timeout(monkeypatch):
    monkeypatch.setattr(runtimes.shutil, "which", lambda name: "/usr/bin/node")

    def fake_run(argv, **kwargs):
        raise subprocess.TimeoutExpired(cmd="node", timeout=1)

    monkeypatch.setattr(runtimes.subprocess, "run", fake_run)
    probe = runtimes.probe_node()
    assert probe.ok is False
    assert probe.error


def test_node_probe_reports_connection_error(monkeypatch):
    monkeypatch.setattr(runtimes.shutil, "which", lambda name: "/usr/bin/node")

    class Proc:
        returncode = 0
        stdout = json.dumps({"ok": False, "error": "ECONNREFUSED"})
        stderr = ""

    monkeypatch.setattr(runtimes.subprocess, "run", lambda *a, **k: Proc())
    probe = runtimes.probe_node()
    assert probe.ok is False
    assert "ECONNREFUSED" in probe.error


def test_node_probe_cleans_up_its_temp_script(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(runtimes.shutil, "which", lambda name: "/usr/bin/node")
    seen = {}

    class Proc:
        returncode = 0
        stdout = json.dumps({"ok": True, "ip": "1.2.3.4", "loc": "SG"})
        stderr = ""

    def fake_run(argv, **kwargs):
        seen["path"] = Path(argv[1])
        assert seen["path"].exists(), "script must exist while node runs"
        return Proc()

    monkeypatch.setattr(runtimes.subprocess, "run", fake_run)
    runtimes.probe_node()
    assert not seen["path"].exists(), "temp script must be removed afterwards"


def test_shell_probe_parses_trace(monkeypatch):
    monkeypatch.setattr(runtimes.shutil, "which", lambda name: "/usr/bin/curl" if name == "curl" else None)

    class Proc:
        returncode = 0
        stdout = "fl=abc\nip=203.0.113.250\nloc=CN\ncolo=LAX\n"
        stderr = ""

    monkeypatch.setattr(runtimes.subprocess, "run", lambda *a, **k: Proc())
    probe = runtimes.probe_shell()
    assert probe.ok and probe.loc == "CN"


def test_collect_runtimes_emits_one_observation_each(monkeypatch):
    monkeypatch.setattr(
        runtimes,
        "probe_node",
        lambda: _node("203.0.113.250", "CN"),
    )
    monkeypatch.setattr(
        runtimes,
        "probe_shell",
        lambda: RuntimeProbe(runtime="shell", label="Shell / curl", available=True, ok=True, ip="203.0.113.250", loc="CN"),
    )
    probes, observations = runtimes.collect_runtimes()
    assert len(probes) == 2
    assert {o.key for o in observations} == {"runtime.node", "runtime.shell"}
    assert all(o.status == "ok" for o in observations)


def test_unavailable_runtime_is_skipped_not_faked(monkeypatch):
    monkeypatch.setattr(
        runtimes,
        "probe_node",
        lambda: RuntimeProbe(runtime="node", label="Node", available=False, error="未安装 node"),
    )
    monkeypatch.setattr(
        runtimes,
        "probe_shell",
        lambda: RuntimeProbe(runtime="shell", label="Shell", available=False, error="未安装 curl"),
    )
    _, observations = runtimes.collect_runtimes()
    assert all(o.status == "skipped" for o in observations)


@pytest.mark.parametrize("var", ["HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "all_proxy"])
def test_env_scrubbing_covers_every_proxy_variable(var: str, monkeypatch):
    monkeypatch.setenv(var, "http://127.0.0.1:7897")
    env = runtimes._env_without_proxy()
    assert var not in env
