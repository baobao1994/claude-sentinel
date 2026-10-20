"""Stage progress plumbing and the SSE scan stream."""

from __future__ import annotations

import json
import threading
from pathlib import Path

import httpx
import pytest

import claude_sentinel.web.server as server_mod
from claude_sentinel.collectors import network
from claude_sentinel.collectors.base import Http
from claude_sentinel.config import Settings
from claude_sentinel.models import ClaudeCodeInfo
from claude_sentinel.pipeline import run_scan
from claude_sentinel.progress import STAGES, TOTAL_STAGES, Tracker, stage_public
from claude_sentinel.web.server import build_server
from tests.test_pipeline_mock import _handler as mock_http


@pytest.fixture()
def mock_settings(tmp_path: Path, monkeypatch):
    """Settings whose collectors are fully mocked, so no network is touched."""
    monkeypatch.setattr(
        network,
        "_curl_trace",
        lambda family, proxy=None: {"ip": "203.0.113.9", "loc": "US", "colo": "LAX", "warp": "off"},
    )
    monkeypatch.setattr(
        "claude_sentinel.pipeline.claude_code.collect_claude_code",
        lambda: (
            ClaudeCodeInfo(
                installed=True,
                version="2.1.273",
                base_url_kind="official",
                auth_modes=["oauth_file"],
            ),
            [],
        ),
    )
    return Settings(home=tmp_path, timeout=3, ip_intel=True)


def _mocked_run_scan(settings, http=None, store=None, progress=None):
    return run_scan(
        settings,
        http=Http(transport=httpx.MockTransport(mock_http)),
        store=store,
        progress=progress,
    )


# ------------------------------------------------------------------ tracker
def test_stage_catalog_is_unique_and_ordered():
    ids = [stage.id for stage in STAGES]
    assert len(ids) == len(set(ids)) == TOTAL_STAGES
    assert [stage["id"] for stage in stage_public()] == ids
    assert {"id", "label", "group", "hint"} == set(stage_public()[0])


def test_scan_emits_a_start_and_a_settle_for_every_stage(mock_settings):
    events: list[tuple] = []
    report = run_scan(
        mock_settings,
        http=Http(transport=httpx.MockTransport(mock_http)),
        progress=lambda *args: events.append(args),
    )
    assert report.verdict.code

    started = {stage_id for stage_id, phase, *_ in events if phase == "start"}
    settled = {stage_id for stage_id, phase, *_ in events if phase != "start"}
    assert started == {stage.id for stage in STAGES}
    # "skip" is a settled state too; every stage must reach a terminal phase.
    assert settled == started
    assert [stage_id for stage_id, phase, *_ in events if phase == "start"][0] == "gate"
    assert events[-1][0] == "verdict"
    assert all(elapsed is None or elapsed >= 0 for _, _, _, elapsed in events)


def test_progress_callback_failure_never_breaks_a_scan(mock_settings):
    def explode(*args):
        raise RuntimeError("UI went away")

    report = run_scan(
        mock_settings,
        http=Http(transport=httpx.MockTransport(mock_http)),
        progress=explode,
    )
    assert report.run_id


def test_tracker_records_failures_without_swallowing_them():
    seen: list[tuple] = []
    tracker = Tracker(lambda *args: seen.append(args))
    with pytest.raises(ValueError):
        with tracker.stage("gate"):
            raise ValueError("boom")
    assert seen[-1][1] == "fail"
    assert "boom" in seen[-1][2]


def test_stage_handle_marks_warn_and_skip():
    seen: list[tuple] = []
    tracker = Tracker(lambda *args: seen.append(args))
    with tracker.stage("edge") as stage:
        stage.warn("trace unreachable")
    with tracker.stage("account") as stage:
        stage.skip("reference mode")
    settled = [(stage_id, phase, detail) for stage_id, phase, detail, _ in seen if phase != "start"]
    assert settled == [
        ("edge", "warn", "trace unreachable"),
        ("account", "skip", "reference mode"),
    ]


# ------------------------------------------------------------------- web API
@pytest.fixture()
def live_server(mock_settings, monkeypatch):
    monkeypatch.setattr(server_mod, "run_scan", _mocked_run_scan)
    server = build_server(mock_settings, host="127.0.0.1", port=0, autostart=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _read_sse(url: str, token: str, timeout: float = 60) -> list[dict]:
    """Minimal SSE client: returns every decoded event in order."""
    import urllib.request

    events: list[dict] = []
    req = urllib.request.Request(
        url,
        data=b"",
        method="POST",
        headers={"X-Sentinel-Token": token, "Accept": "text/event-stream"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as response:
        assert response.headers["Content-Type"].startswith("text/event-stream")
        event = "message"
        for raw in response:
            line = raw.decode("utf-8").rstrip("\n")
            if line.startswith("event:"):
                event = line[6:].strip()
            elif line.startswith("data:"):
                events.append({"event": event, "data": json.loads(line[5:].strip())})
            elif line == "":
                event = "message"
    return events


def test_sse_stream_reports_each_stage_then_the_report(live_server):
    url = f"http://127.0.0.1:{live_server.server_address[1]}/api/scan/stream"
    events = _read_sse(url, live_server.token)
    kinds = [item["event"] for item in events]
    assert kinds[0] == "open"
    assert kinds.count("open") == 1
    assert kinds.count("report") == 1
    assert kinds[-1] == "done"

    stage_events = [item["data"] for item in events if item["event"] == "stage"]
    assert {item["id"] for item in stage_events if item["phase"] == "start"} == {
        stage.id for stage in STAGES
    }
    assert all(item["at_ms"] >= 0 for item in stage_events)

    report = next(item["data"] for item in events if item["event"] == "report")
    assert report["report"]["run_id"]
    assert report["report"]["verdict"]["headline"]
    assert isinstance(report["history"], list)
    assert report["duration_ms"] >= 0


def test_sse_requires_the_process_token(live_server):
    import urllib.error
    import urllib.request

    url = f"http://127.0.0.1:{live_server.server_address[1]}/api/scan/stream"
    req = urllib.request.Request(url, data=b"", method="POST", headers={"X-Sentinel-Token": "nope"})
    with pytest.raises(urllib.error.HTTPError) as excinfo:
        urllib.request.urlopen(req, timeout=10)
    assert excinfo.value.code == 403


def test_meta_exposes_stages_and_autostart(live_server):
    import urllib.request

    url = f"http://127.0.0.1:{live_server.server_address[1]}/api/meta"
    with urllib.request.urlopen(url, timeout=10) as response:
        meta = json.load(response)
    assert [stage["id"] for stage in meta["stages"]] == [stage.id for stage in STAGES]
    assert meta["autostart"] is True


def test_only_one_scan_at_a_time(live_server):
    """The second concurrent stream must be refused rather than queued."""
    import urllib.error
    import urllib.request

    base = f"http://127.0.0.1:{live_server.server_address[1]}/api/scan/stream"

    def open_stream():
        req = urllib.request.Request(
            base, data=b"", method="POST", headers={"X-Sentinel-Token": live_server.token}
        )
        return urllib.request.urlopen(req, timeout=60)

    first = open_stream()
    try:
        # Drain the "open" frame so the handler is definitely inside the scan.
        first.readline()
        with pytest.raises(urllib.error.HTTPError) as excinfo:
            open_stream()
        assert excinfo.value.code == 409
    finally:
        first.close()


# --------------------------------------------------------------- launchers
def test_launcher_scripts_are_executable():
    root = Path(__file__).resolve().parents[1]
    for name in ("sentinel-live.command", "sentinel.sh"):
        path = root / name
        assert path.exists(), f"{name} is missing"
        assert path.stat().st_mode & 0o111, f"{name} must be executable"
        text = path.read_text(encoding="utf-8")
        assert text.startswith("#!/bin/bash")
        assert "uv sync" in text  # first-run bootstrap
