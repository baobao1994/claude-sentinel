from __future__ import annotations

from pathlib import Path

from claude_sentinel.config import Settings
from claude_sentinel.models import Observation, Source, Status
from claude_sentinel.render.html import build_view, render_html
from tests.conftest import make_report


def test_render_html_self_contained(tmp_path: Path):
    report = make_report()
    path = tmp_path / "report.html"
    render_html(report, path, Settings(home=tmp_path))
    text = path.read_text(encoding="utf-8")
    assert "可以，但建议先处理" in text
    assert "六轴信号" in text
    assert text.count("<script") == 1


def test_build_view_masks_ip_by_default(tmp_path: Path):
    report = make_report(
        observations={
            "net.edge": Observation(
                key="net.edge",
                label="edge",
                value={"ip": "203.0.113.9"},
                detail="203.0.113.9 · US",
                status=Status.ok,
                source=Source(name="edge", kind="edge"),
            )
        }
    )
    view = build_view(report, Settings(home=tmp_path, show_ip=False))
    import json

    assert "203.0.113.9" not in json.dumps(view, ensure_ascii=False)
    assert view["environment"]["ip"] == "203.0.*.*"
    assert view["environment"]["full_ip"] is None
    assert view["score_display"] == "20"


def test_build_view_can_show_ip(tmp_path: Path):
    report = make_report()
    view = build_view(report, Settings(home=tmp_path, show_ip=True))
    assert view["environment"]["ip"] == "203.0.113.9"
    assert view["environment"]["full_ip"] == "203.0.113.9"
