from __future__ import annotations

from pathlib import Path

from claude_sentinel.collectors.local import _machine_fingerprint


def test_fingerprint_is_stable(tmp_path: Path):
    first = _machine_fingerprint(tmp_path)
    second = _machine_fingerprint(tmp_path)
    assert first == second
    assert (tmp_path / "device_id").exists()
    assert len(first) == 16


def test_fingerprint_differs_by_home(tmp_path: Path):
    other = tmp_path / "other"
    assert _machine_fingerprint(tmp_path) != _machine_fingerprint(other)
