from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from claude_sentinel.cli import _exit_code, app
from claude_sentinel.models import VerdictCode


def test_version():
    result = CliRunner().invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "claude-sentinel" in result.output


def test_rules_command():
    result = CliRunner().invoke(app, ["rules"])
    assert result.exit_code == 0
    assert "ip.proxy_vpn" in result.output


def test_sources_command():
    result = CliRunner().invoke(app, ["sources"])
    assert result.exit_code == 0
    assert "status.claude.com" in result.output


def test_history_empty(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("CLAUDE_SENTINEL_HOME", str(tmp_path))
    result = CliRunner().invoke(app, ["history"])
    assert result.exit_code == 0
    assert "暂无历史" in result.output


def test_exit_codes():
    assert _exit_code(VerdictCode.ready) == 0
    assert _exit_code(VerdictCode.caution) == 1
    assert _exit_code(VerdictCode.high_caution) == 2
    assert _exit_code(VerdictCode.do_not_start) == 2
    assert _exit_code(VerdictCode.blocked_region) == 3
    assert _exit_code(VerdictCode.unknown) == 4


def test_scan_alias_help():
    result = CliRunner().invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--json" in result.output
    assert "--no-ip-intel" in result.output


def test_account_json_help():
    result = CliRunner().invoke(app, ["account", "--help"])
    assert result.exit_code == 0
    assert "--json" in result.output
