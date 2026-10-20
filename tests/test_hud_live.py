"""Terminal live HUD: rendering, phase states, and non-TTY fallback."""

from __future__ import annotations

from rich.console import Console

from claude_sentinel.progress import STAGES, TOTAL_STAGES
from claude_sentinel.render.hud_live import TerminalScanner


def _scanner(enabled: bool = False, width: int = 100) -> tuple[TerminalScanner, Console]:
    console = Console(width=width, force_terminal=False)
    scanner = TerminalScanner(console, enabled=enabled)
    scanner.enabled = enabled  # bypass the TTY probe in tests
    return scanner, console


def _plain(console: Console, renderable) -> str:
    with console.capture() as capture:
        console.print(renderable)
    return capture.get()


def test_hud_starts_all_pending():
    scanner, _ = _scanner()
    text = _plain(scanner.console, scanner._render())
    assert "ENVIRONMENT SWEEP" in text
    assert f"0/{TOTAL_STAGES}" in text
    assert "READ-ONLY" in text
    assert scanner.done_count == 0


def test_hud_tracks_every_phase_glyph():
    scanner, _ = _scanner()
    scanner.progress("gate", "start", None, None)
    scanner.progress("gate", "done", "区域闸门通过", 100)
    scanner.progress("regions", "start", None, None)
    scanner.progress("regions", "done", "185 个支持地区", 90)
    scanner.progress("edge", "warn", "边缘 trace 不可达", 50)
    scanner.progress("account", "skip", "参考模式", 1)
    scanner.progress("dns", "fail", "boom", 5)

    text = _plain(scanner.console, scanner._render())
    # gate + regions (done), edge (warn), account (skip), dns (fail).
    assert "5/" in text and str(TOTAL_STAGES) in text
    assert scanner.done_count == 5
    # Only a window of the list is shown; the most recent failure is in it.
    assert "DNS 解析器" in text
    assert "boom" in text


def test_hud_shows_early_stage_details_before_the_list_scrolls():
    scanner, _ = _scanner()
    scanner.progress("gate", "done", "区域闸门通过", 100)
    scanner.progress("regions", "start", None, None)
    text = _plain(scanner.console, scanner._render())
    assert "区域闸门通过" in text
    assert "边缘 trace 不可达" not in text


def test_hud_windows_the_stage_list_around_the_active_stage():
    scanner, _ = _scanner()
    for stage in STAGES:
        scanner.states[stage.id] = "done"
    scanner.states[STAGES[-1].id] = "start"
    text = _plain(scanner.console, scanner._render())
    assert STAGES[-1].label in text
    assert STAGES[0].label not in text  # scrolled out of the 9-row window


def test_hud_marks_completion():
    scanner, _ = _scanner()
    for stage in STAGES:
        scanner.states[stage.id] = "done"
    text = _plain(scanner.console, scanner._render(final=True))
    assert "检测完成" in text
    assert f"{TOTAL_STAGES}/{TOTAL_STAGES}" in text
    assert "项待检测" not in text


def test_hud_is_silent_without_a_tty():
    console = Console(width=100, force_terminal=False)
    scanner = TerminalScanner(console, enabled=True)  # console is not a tty
    assert scanner.enabled is False
    with scanner:
        scanner.progress("gate", "start", None, None)
    assert scanner.states["gate"] == "start"


def test_progress_for_unknown_stage_is_ignored():
    scanner, _ = _scanner()
    scanner.progress("not-a-stage", "done", "huh", 1)
    assert "not-a-stage" not in scanner.states
