from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from claude_sentinel import launch


class _Recorder:
    def __init__(self) -> None:
        self.args: list[list[str]] = []

    def __call__(self, argv, **kwargs):
        self.args.append(list(argv))

        class _Proc:
            pass

        return _Proc()


def test_app_window_uses_a_dedicated_profile(monkeypatch, tmp_path: Path):
    mac = tmp_path / "Google Chrome"
    mac.write_text("")
    monkeypatch.setattr(launch, "find_app_browser", lambda: mac)
    recorder = _Recorder()
    monkeypatch.setattr(subprocess, "Popen", recorder)

    surface = launch.launch(
        "http://127.0.0.1:8765/",
        app_window=True,
        width=1440,
        height=940,
        profile_dir=tmp_path / "profile",
    )

    assert surface == "app"
    argv = recorder.args[0]
    assert argv[0] == str(mac)
    assert "--app=http://127.0.0.1:8765/" in argv
    assert "--window-size=1440,940" in argv
    assert any(arg.startswith("--user-data-dir=") for arg in argv)
    assert (tmp_path / "profile").is_dir()


def test_falls_back_to_a_tab_when_no_app_browser(monkeypatch):
    monkeypatch.setattr(launch, "find_app_browser", lambda: None)
    monkeypatch.setattr(launch.webbrowser, "open", lambda url: True)

    assert launch.launch("http://127.0.0.1:8765/", app_window=True) == "tab"


def test_falls_back_to_a_tab_when_launching_fails(monkeypatch, tmp_path: Path):
    mac = tmp_path / "Google Chrome"
    mac.write_text("")
    monkeypatch.setattr(launch, "find_app_browser", lambda: mac)
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: (_ for _ in ()).throw(OSError("nope")))
    monkeypatch.setattr(launch.webbrowser, "open", lambda url: True)

    assert launch.launch("http://127.0.0.1:8765/", app_window=True) == "tab"


def test_reports_manual_when_everything_fails(monkeypatch):
    monkeypatch.setattr(launch, "find_app_browser", lambda: None)
    monkeypatch.setattr(launch.webbrowser, "open", lambda url: False)

    assert launch.launch("http://127.0.0.1:8765/") == "manual"


def test_app_browser_lookup_is_macos_resolved(monkeypatch, tmp_path: Path):
    """Chrome paths resolve only when the binary exists."""
    chrome = tmp_path / "Google Chrome.app/Contents/MacOS/Google Chrome"
    chrome.parent.mkdir(parents=True)
    chrome.write_text("")
    monkeypatch.setattr(launch, "MAC_APP_CANDIDATES", (("Google Chrome", str(chrome)),))
    monkeypatch.setattr(launch.sys, "platform", "darwin")
    assert launch.find_app_browser() == chrome

    monkeypatch.setattr(launch.sys, "platform", "linux")
    assert launch.find_app_browser() is None


@pytest.mark.parametrize("name", ["Google Chrome", "Microsoft Edge"])
def test_candidate_table_is_well_formed(name):
    assert any(entry[0] == name for entry in launch.MAC_APP_CANDIDATES)
