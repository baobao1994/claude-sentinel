"""Live terminal scan HUD, driven by the same stage events as the web panel."""

from __future__ import annotations

from time import perf_counter

from rich.console import Console, Group
from rich.live import Live
from rich.text import Text

from claude_sentinel.progress import STAGES, Stage

CYAN = "#22D3EE"
GREEN = "#34D399"
AMBER = "#F59E0B"
RED = "#F43F5E"
MUTED = "#6B8299"
TEXT = "#E5F2FF"
VIOLET = "#A78BFA"

PHASE_GLYPH = {
    "pending": ("·", MUTED),
    "start": ("◐", CYAN),
    "done": ("✓", GREEN),
    "warn": ("!", AMBER),
    "fail": ("✕", RED),
    "skip": ("–", MUTED),
}

SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
TICKS = "░▒▓█"


def _bar(done: int, total: int, width: int = 34) -> Text:
    filled = int(round(done / total * width)) if total else 0
    text = Text()
    text.append("█" * filled, style=f"bold {CYAN}")
    text.append("░" * (width - filled), style="#12212E")
    return text


class TerminalScanner:
    """Renders a live stage list; falls back to a no-op outside a TTY.

    Used as a context manager:

        with TerminalScanner(console, enabled=...) as scanner:
            report = run_scan(settings, progress=scanner.progress)
    """

    def __init__(
        self,
        console: Console,
        *,
        enabled: bool = True,
        max_rows: int = 9,
    ) -> None:
        self.console = console
        self.enabled = enabled and console.is_terminal
        self.max_rows = max_rows
        self.states: dict[str, str] = {stage.id: "pending" for stage in STAGES}
        self.details: dict[str, str] = {}
        self.started = perf_counter()
        self._live: Live | None = None
        self._frame = 0
        self._current: str | None = None
        self._last_index: int | None = None

    # ------------------------------------------------------------- lifecycle
    def __enter__(self) -> TerminalScanner:
        if self.enabled:
            self._live = Live(
                self._render(),
                console=self.console,
                refresh_per_second=12,
                transient=False,
                vertical_overflow="visible",
            )
            self._live.__enter__()
        return self

    def __exit__(self, *exc: object) -> None:
        if self._live is not None:
            self._live.update(self._render(final=True))
            self._live.stop()
            self._live = None
            # The verdict panel below is the real answer: drop the HUD so the
            # recording does not end on a wall of stale stage rows.
            self.console.print()

    # -------------------------------------------------------------- progress
    def progress(
        self,
        stage_id: str,
        phase: str,
        detail: str | None,
        elapsed_ms: int | None,
    ) -> None:
        if stage_id not in self.states:
            return
        self.states[stage_id] = phase
        if detail and phase != "start":
            self.details[stage_id] = detail
        if phase == "start":
            self._current = stage_id
        # Track the row the action is on: a stage can settle without a "start"
        # (or fail straight away), and the window must follow that row.
        for index, stage in enumerate(STAGES):
            if stage.id == stage_id:
                self._last_index = index
                break
        if self._live is not None:
            self._live.update(self._render())

    @property
    def done_count(self) -> int:
        return sum(1 for state in self.states.values() if state in {"done", "warn", "fail", "skip"})

    # ---------------------------------------------------------------- render
    def _render(self, final: bool = False) -> Group:
        self._frame += 1
        done = self.done_count
        total = len(STAGES)
        percent = int(round(done / total * 100)) if total else 0
        elapsed = perf_counter() - self.started

        header = Text()
        header.append("  ENVIRONMENT SWEEP ", style=f"bold {CYAN}")
        header.append(f"{done}/{total}".rjust(7), style=MUTED)
        header.append(f"   {percent:3d}%", style=f"bold {TEXT}")
        header.append(f"   {elapsed:4.1f}s", style=MUTED)

        current = self._next_pending() if not final else None
        if final:
            headline = Text("  检测完成", style=f"bold {GREEN}")
        else:
            spinner = SPINNER[self._frame % len(SPINNER)] if self.enabled else "◐"
            label = self._label(self._current) or self._label(current) or "初始化"
            headline = Text()
            headline.append(f"  {spinner} ", style=CYAN)
            headline.append(label, style=f"bold {TEXT}")

        bar = Text("  ")
        bar.append_text(_bar(done, total))
        bar.append(f"  {percent}%", style=MUTED)

        rows = [header, Text(), headline, bar, Text()]

        # Window the stage list around the active row.
        active_index = self._active_index()
        start = max(0, min(active_index - self.max_rows // 2, total - self.max_rows))
        for stage in STAGES[start : start + self.max_rows]:
            rows.append(self._stage_row(stage))

        footer = Text()
        footer.append("  READ-ONLY · NO UPLOAD · LOCAL ONLY", style=MUTED)
        unknown = total - done
        if unknown:
            footer.append(f"   {unknown} 项待检测", style=MUTED)
        rows.extend([Text(), footer])
        return Group(*rows)

    def _stage_row(self, stage: Stage) -> Text:
        state = self.states.get(stage.id, "pending")
        glyph, color = PHASE_GLYPH.get(state, ("·", MUTED))
        row = Text()
        row.append(f"   {glyph} ", style=f"bold {color}")
        style = f"bold {TEXT}" if state == "start" else (MUTED if state == "pending" else TEXT)
        row.append(stage.label.ljust(12, "　"), style=style)
        detail = self.details.get(stage.id) or stage.hint
        if state == "pending":
            row.append("—", style=MUTED)
        else:
            row.append(str(detail)[:56], style=f"bold {color}" if state in {"warn", "fail"} else MUTED)
        return row

    def _active_index(self) -> int:
        for index, stage in enumerate(STAGES):
            if self.states.get(stage.id) == "start":
                return index
        if self._last_index is not None:
            return self._last_index
        for index in range(len(STAGES) - 1, -1, -1):
            if self.states.get(STAGES[index].id) in {"done", "warn", "fail", "skip"}:
                return index
        return 0

    def _next_pending(self) -> str | None:
        for stage in STAGES:
            if self.states.get(stage.id) == "pending":
                return stage.id
        return None

    @staticmethod
    def _label(stage_id: str | None) -> str | None:
        if not stage_id:
            return None
        for stage in STAGES:
            if stage.id == stage_id:
                return stage.label
        return None
