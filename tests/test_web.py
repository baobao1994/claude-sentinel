from __future__ import annotations

import json
from pathlib import Path

from claude_sentinel.config import Settings
from claude_sentinel.history import HistoryStore
from claude_sentinel.web.server import _history_rows, _public
from tests.conftest import make_report


def test_web_public_api_redacts_ips(tmp_path: Path):
    report = make_report()
    data = _public(report, Settings(home=tmp_path, show_ip=False))
    text = json.dumps(data, ensure_ascii=False)
    assert "203.0.113.9" not in text
    assert "203.0.*.*" in text


def test_web_history_rows_have_no_full_ip(tmp_path: Path):
    store = HistoryStore(tmp_path / "h.db")
    store.save(make_report())
    rows = _history_rows(store, 5)
    assert rows
    assert rows[0]["ip_masked"] == "203.0.*.*"
    assert "ip" not in rows[0]
