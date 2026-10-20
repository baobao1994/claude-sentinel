"""Terminal HUD renderer (Rich)."""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from claude_sentinel.config import Settings
from claude_sentinel.models import (
    Confidence,
    Report,
    Severity,
    Status,
    VerdictCode,
)
from claude_sentinel.redact import redact_text

CYAN = "#22D3EE"
GREEN = "#34D399"
AMBER = "#F59E0B"
RED = "#F43F5E"
MUTED = "#6B8299"
TEXT = "#E5F2FF"
VIOLET = "#A78BFA"

VERDICT_COLORS = {
    VerdictCode.ready: GREEN,
    VerdictCode.caution: CYAN,
    VerdictCode.high_caution: AMBER,
    VerdictCode.do_not_start: RED,
    VerdictCode.blocked_region: RED,
    VerdictCode.blocked_account: RED,
    VerdictCode.blocked_service: AMBER,
    VerdictCode.blocked_clock: AMBER,
    VerdictCode.unknown: MUTED,
}

STATUS_GLYPH = {
    Status.ok: ("✓", GREEN),
    Status.info: ("·", CYAN),
    Status.warn: ("!", AMBER),
    Status.high: ("✕", RED),
    Status.unknown: ("?", MUTED),
    Status.skipped: ("-", MUTED),
}

SEVERITY_ZH = {
    Severity.critical: "极高",
    Severity.high: "高",
    Severity.medium: "中",
    Severity.low: "低",
    Severity.info: "信息",
}

SEVERITY_COLOR = {
    Severity.critical: RED,
    Severity.high: RED,
    Severity.medium: AMBER,
    Severity.low: CYAN,
    Severity.info: MUTED,
}

CONFIDENCE_ZH = {
    Confidence.high: "高",
    Confidence.medium: "中",
    Confidence.low: "低",
}


def _logo() -> Text:
    art = r"""
   ██████╗██╗      █████╗ ██╗   ██╗██████╗ ███████╗
  ██╔════╝██║     ██╔══██╗██║   ██║██╔══██╗██╔════╝
  ██║     ██║     ███████║██║   ██║██║  ██║█████╗
  ██║     ██║     ██╔══██║██║   ██║██║  ██║██╔══╝
  ╚██████╗███████╗██║  ██║╚██████╔╝██████╔╝███████╗
   ╚═════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝
"""
    text = Text()
    for line in art.strip("\n").splitlines():
        text.append(line + "\n", style=f"bold {CYAN}")
    text.append("  S E N T I N E L", style=f"bold {MUTED}")
    text.append("   local · read-only · evidence-first", style=MUTED)
    return text


def _bar(score: float | None, width: int = 22) -> Text:
    """Safety bar: a longer, greener bar means a safer environment."""
    text = Text()
    if score is None:
        text.append("░" * width, style=MUTED)
        return text
    filled = max(0, min(width, int(round(score / 100 * width))))
    color = GREEN if score >= 86 else (CYAN if score >= 66 else (AMBER if score >= 41 else RED))
    text.append("█" * filled, style=f"bold {color}")
    text.append("░" * (width - filled), style=MUTED)
    return text


def _fmt_time(value: datetime | None) -> str:
    if value is None:
        return "—"
    try:
        return value.astimezone().strftime("%Y-%m-%d %H:%M")
    except Exception:
        return value.isoformat()


def _drift_summary(report: Report) -> str:
    if report.history.is_baseline:
        return "首次运行 · 已记录基线"
    changed = [d for d in report.drift if d.changed]
    if not changed:
        return f"上次 {_fmt_time(report.history.last_run_at)} · 无变化"
    labels = "、".join(d.label for d in changed[:3])
    return f"上次 {_fmt_time(report.history.last_run_at)} · 变化：{labels}"


def _section_table(report: Report, settings: Settings) -> Table:
    table = Table.grid(padding=(0, 1))
    table.add_column(width=18, no_wrap=True)
    table.add_column(ratio=1)
    table.add_column(width=10, no_wrap=True, justify="right")

    env = report.environment
    region = report.observations.get("official.region_gate")
    region_value = region.value if region and isinstance(region.value, dict) else {}
    available = region_value.get("available")
    if available is False:
        region_text = "region_unavailable"
        region_status = Status.high
    elif (
        available is True
        and report.regions
        and env.country_code
        and env.country_code not in report.regions.codes
    ):
        region_text = "gate OK / IP 不支持"
        region_status = Status.warn
    elif available is True:
        region_text = "可用"
        region_status = Status.ok
    else:
        region_text = "无法判断"
        region_status = Status.unknown

    ip_value = env.ip if settings.show_ip else env.ip_masked
    egress_text = f"{ip_value or '—'}  {env.country_code or '?'}  {env.asn or '—'}"

    tz = report.local.timezone if report.local else env.timezone
    locale = report.local.locale if report.local else env.locale
    browser = env.browser or "—"
    identity_text = f"{tz or '?'} · {locale or '?'} · {browser}"

    if report.client:
        version = report.client.version or "?"
        endpoint = {
            "official": "official",
            "third_party": "third-party",
            "invalid": "invalid",
            "unset": "unset",
        }.get(report.client.base_url_kind, report.client.base_url_kind)
        auth = "/".join(report.client.auth_modes) or "none"
        client_text = f"claude {version} · {endpoint} · {auth}"
    else:
        client_text = "—"

    account_state = report.account.state if report.account else "unverified"
    account_text = {
        "active": "active",
        "expired": "expired",
        "disabled": "disabled",
        "region_blocked": "region",
        "challenge": "challenge",
    }.get(account_state, "unverified")

    rows = [
        ("01 OFFICIAL GATE", region_text, region_status),
        ("02 EGRESS", egress_text, Status.ok if env.ip else Status.unknown),
        ("03 IDENTITY", identity_text, Status.ok),
        ("04 CLIENT", client_text, Status.high if report.client and report.client.base_url_kind == "third_party" else Status.ok),
        ("05 ACCOUNT", account_text, Status.ok if account_state == "active" else (Status.high if account_state == "disabled" else Status.unknown)),
        (
            "06 HISTORY",
            _drift_summary(report),
            Status.warn
            if any(d.changed and d.severity in {Severity.high, Severity.critical} for d in report.drift)
            else Status.ok,
        ),
    ]
    for label, value, status in rows:
        glyph, color = STATUS_GLYPH.get(status, ("·", MUTED))
        table.add_row(
            Text(label, style=f"bold {MUTED}"),
            Text(value, style=TEXT),
            Text(f"{glyph} {status.value.upper()}", style=f"bold {color}"),
        )
    return table


def _verdict_panel(report: Report) -> Panel:
    verdict = report.verdict
    color = VERDICT_COLORS.get(verdict.code, MUTED)
    lines = Text()
    lines.append(verdict.headline, style=f"bold {color}")
    lines.append(f"   {verdict.title}\n", style=MUTED)
    lines.append(verdict.reason + "\n", style=TEXT)
    lines.append("SAFETY ", style=MUTED)
    if report.score is None:
        lines.append("— / 100", style=f"bold {MUTED}")
        lines.append("   (硬闸门短路)", style=MUTED)
    else:
        lines.append(f"{report.score:.0f} / 100", style=f"bold {color}")
        lines.append(" 安全分，越高越安全", style=MUTED)
        lines.append("   ")
        lines.append_text(_bar(report.score))
        basis = _score_basis_line(report)
        if basis:
            lines.append("\n")
            lines.append(basis, style=MUTED)
    lines.append(f"   置信度 {CONFIDENCE_ZH.get(report.confidence, report.confidence.value)}", style=MUTED)
    lines.append("\n")
    lines.append(verdict.account_note, style=MUTED)
    return Panel(lines, border_style=color, box=box.HEAVY, padding=(0, 1), title="VERDICT", title_align="left")


def _fix_panel(report: Report) -> Panel | None:
    fixes = report.verdict.top_fixes
    if not fixes:
        return None
    table = Table.grid(padding=(0, 1))
    table.add_column(width=3, justify="right")
    table.add_column(ratio=1)
    for index, fix in enumerate(fixes, 1):
        table.add_row(Text(f"{index}.", style=f"bold {CYAN}"), Text(fix, style=TEXT))
    return Panel(table, border_style=CYAN, box=box.ROUNDED, title="FIX ORDER", title_align="left", padding=(0, 1))


def _findings_table(report: Report, settings: Settings, limit: int = 8) -> Table | None:
    findings = [
        f
        for f in report.findings
        if f.status in {Status.high, Status.warn} and f.max_points > 0
    ]
    if not findings:
        return None
    findings.sort(key=lambda f: (0 if f.severity in {Severity.critical, Severity.high} else 1, -f.points))
    table = Table(
        box=box.SIMPLE_HEAD,
        border_style=MUTED,
        header_style=f"bold {MUTED}",
        expand=True,
        show_edge=False,
    )
    table.add_column("", width=3, no_wrap=True)
    table.add_column("发现", ratio=3)
    table.add_column("证据", ratio=5)
    table.add_column("分值", width=6, justify="right")
    for finding in findings[:limit]:
        color = SEVERITY_COLOR.get(finding.severity, MUTED)
        table.add_row(
            Text("●", style=color),
            Text(finding.title, style=TEXT),
            Text(redact_text(finding.evidence) if not settings.show_ip else finding.evidence, style=MUTED),
            Text(f"{finding.points:.0f}/{finding.max_points:.0f}", style=color),
        )
    return table


def _explain_table(report: Report, settings: Settings) -> Table:
    table = Table(
        box=box.SIMPLE_HEAD,
        border_style=MUTED,
        header_style=f"bold {MUTED}",
        expand=True,
        show_edge=False,
    )
    table.add_column("规则", width=30, no_wrap=True)
    table.add_column("状态", width=8)
    table.add_column("分值", width=9, justify="right")
    table.add_column("证据", ratio=1)
    for finding in sorted(report.findings, key=lambda f: (f.category.value, f.rule_id)):
        glyph, color = STATUS_GLYPH.get(finding.status, ("·", MUTED))
        table.add_row(
            Text(finding.rule_id, style=TEXT),
            Text(f"{glyph} {finding.status.value}", style=color),
            Text(f"{finding.points:.0f}/{finding.max_points:.0f}", style=color),
            Text(redact_text(finding.evidence) if not settings.show_ip else finding.evidence, style=MUTED),
        )
    return table


def _source_line(report: Report) -> Text:
    text = Text()
    text.append("DATA  ", style=f"bold {MUTED}")
    official = [s for s in report.sources if s.kind.value == "official"]
    edge = [s for s in report.sources if s.kind.value == "edge"]
    third = [s for s in report.sources if s.kind.value == "third_party"]
    text.append(
        f"official {len(official)} · edge {len(edge)} · third-party {len(third)} · "
        f"coverage {report.coverage * 100:.0f}%",
        style=MUTED,
    )
    return text


def render_report(
    report: Report,
    settings: Settings,
    report_path: Path | None = None,
    console: Console | None = None,
) -> Console:
    no_color = bool(os.environ.get("NO_COLOR"))
    if console is None:
        console = Console(no_color=no_color, highlight=False)
    elif no_color:
        console.no_color = True
    compact = settings.compact or console.width < 76

    if not compact:
        console.print(_logo())
        console.print()

    header = Text()
    header.append("LOCAL ONLY", style=f"bold {GREEN}")
    header.append("  ·  REFERENCE" if report.account is None else "  ·  ACCOUNT VERIFIED", style=MUTED)
    header.append("  ·  READ-ONLY  ·  ", style=MUTED)
    header.append(f"v{report.app_version}", style=TEXT)
    header.append("  ·  ", style=MUTED)
    header.append(_fmt_time(report.started_at), style=TEXT)
    console.print(Panel(header, box=box.ROUNDED, border_style=MUTED, padding=(0, 1)))

    console.print(_verdict_panel(report))
    console.print()

    console.print(Panel(_section_table(report, settings), box=box.ROUNDED, border_style=MUTED, padding=(0, 1)))

    fix_panel = _fix_panel(report)
    if fix_panel:
        console.print()
        console.print(fix_panel)

    if not compact:
        table = _findings_table(report, settings)
        if table:
            console.print()
            console.print(table)

    if settings.explain:
        console.print()
        console.print(Panel(_explain_table(report, settings), box=box.ROUNDED, border_style=MUTED, title="RULE EXPLAIN", title_align="left"))

    if report.errors:
        console.print()
        console.print(Text("数据源提示", style=f"bold {AMBER}"))
        for error in report.errors[:6]:
            message = error if settings.show_ip else redact_text(error)
            console.print(Text(f"  · {message}", style=MUTED))

    console.print()
    console.print(_source_line(report))
    if report_path:
        console.print(Text(f"报告  {report_path}", style=MUTED))
    for disclaimer in report.disclaimers[:2]:
        console.print(Text(f"! {disclaimer}", style=MUTED))
    return console

def _score_basis_line(report: Report) -> str | None:
    """Explain how the number was produced, so it is auditable at a glance."""
    basis = report.score_basis or {}
    averaged = basis.get("averaged")
    cap = basis.get("cap")
    if averaged is None and cap is None:
        return None
    parts = []
    if averaged is not None:
        parts.append(f"六轴加权平均 {averaged:.0f}")
    cap = basis.get("cap")
    if cap is not None and basis.get("capped"):
        parts.append(
            f"但 {basis.get('cap_rule')}（{basis.get('cap_severity')}）"
            f"封顶 {cap:.0f}，取较低者"
        )
    elif cap is not None:
        parts.append(f"最严重项 {basis.get('cap_rule')} 约 {cap:.0f}")
    return "算法：" + "；".join(parts) if parts else None
