"""Self-contained HTML report renderer."""

from __future__ import annotations

import json
import math
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from claude_sentinel.config import Settings
from claude_sentinel.models import (
    Report,
    Severity,
    Status,
    VerdictCode,
)
from claude_sentinel.redact import redact_text

VERDICT_COLORS = {
    VerdictCode.ready: "#34D399",
    VerdictCode.caution: "#22D3EE",
    VerdictCode.high_caution: "#F59E0B",
    VerdictCode.do_not_start: "#F43F5E",
    VerdictCode.blocked_region: "#F43F5E",
    VerdictCode.blocked_account: "#F43F5E",
    VerdictCode.blocked_service: "#F59E0B",
    VerdictCode.blocked_clock: "#F59E0B",
    VerdictCode.unknown: "#6B8299",
}

SEVERITY_ZH = {
    Severity.critical: "极高",
    Severity.high: "高",
    Severity.medium: "中",
    Severity.low: "低",
    Severity.info: "信息",
}

LEVEL_ZH = {
    "low": "低",
    "medium": "中",
    "high": "高",
    "critical": "极高",
    "blocked": "硬闸门",
    "unknown": "未知",
}

STATUS_ZH = {
    Status.ok: "通过",
    Status.info: "信息",
    Status.warn: "提醒",
    Status.high: "高危",
    Status.unknown: "未知",
    Status.skipped: "跳过",
}

VISIBILITY_ZH = {
    "server": "Claude 服务器可见",
    "browser_js": "Claude 网页 JS 可读",
    "local": "仅本机可见",
}

RADAR_LABELS = [
    ("ip", "出口信誉"),
    ("stability", "稳定性"),
    ("identity", "身份一致性"),
    ("client", "客户端"),
    ("account", "账号"),
    ("behavior", "行为"),
]


def _fmt_time(value) -> str:
    if value is None:
        return "—"
    try:
        return value.astimezone().strftime("%Y-%m-%d %H:%M")
    except Exception:
        return str(value)


def _clean(value: Any, show_ip: bool) -> Any:
    if value is None or show_ip:
        return value
    return redact_text(str(value))


def _truncate(value: Any, limit: int = 90) -> str:
    if isinstance(value, (dict, list)):
        text = json.dumps(value, ensure_ascii=False)
    else:
        text = str(value) if value is not None else "—"
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _score_basis_text(report: Report) -> str | None:
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
            f"{basis.get('cap_rule')}（{basis.get('cap_severity')}）"
            f"封顶 {cap:.0f}，取较低者"
        )
    elif cap is not None:
        parts.append(f"最严重项 {basis.get('cap_rule')} 约 {cap:.0f}")
    return "算法：" + "；".join(parts) if parts else None


def build_view(
    report: Report,
    settings: Settings,
    history_runs: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    env = report.environment
    ip = env.ip if settings.show_ip else env.ip_masked
    color = VERDICT_COLORS.get(report.verdict.code, "#6B8299")

    findings: list[dict[str, Any]] = []
    for finding in report.findings:
        if finding.status == Status.ok:
            continue
        if finding.max_points <= 0 and finding.status == Status.info:
            continue
        findings.append(
            {
                "rule_id": finding.rule_id,
                "title": finding.title,
                "severity": str(finding.severity),
                "severity_zh": SEVERITY_ZH.get(finding.severity, ""),
                "status": str(finding.status),
                "status_zh": STATUS_ZH.get(finding.status, ""),
                "points": round(finding.points, 1),
                "max_points": round(finding.max_points, 1),
                "evidence": _clean(finding.evidence, settings.show_ip),
                "fix": _clean(finding.fix, settings.show_ip),
                "visibility": str(finding.visibility),
                "visibility_zh": VISIBILITY_ZH.get(str(finding.visibility), ""),
                "confidence": str(finding.confidence),
                "sources": [
                    {"name": source.name, "url": _clean(source.url, settings.show_ip)}
                    for source in finding.sources
                ],
                "is_gate": finding.max_points <= 0,
            }
        )
    order = {Severity.critical: 0, Severity.high: 1, Severity.medium: 2, Severity.low: 3, Severity.info: 4}
    findings.sort(key=lambda f: (order.get(Severity(f["severity"]), 9), -f["points"]))

    categories = []
    radar = []
    by_cat = {str(c.category): c for c in report.categories}
    for key, label in RADAR_LABELS:
        item = by_cat.get(key)
        score = item.score if item and item.score is not None else 0
        radar.append({"label": label, "value": score, "available": bool(item and item.score is not None)})
        categories.append(
            {
                "key": key,
                "label": label,
                "score": score if item and item.score is not None else None,
                "coverage": round(item.coverage * 100) if item else 0,
                "weight": item.weight if item else 0,
            }
        )

    obs_groups = []
    for vis in ("server", "browser_js", "local"):
        items = []
        for obs in report.observations.values():
            if str(obs.visibility) != vis:
                continue
            items.append(
                {
                    "label": obs.label,
                    "value": _clean(_truncate(obs.value), settings.show_ip),
                    "status": str(obs.status),
                    "status_zh": STATUS_ZH.get(obs.status, ""),
                    "detail": _clean(_truncate(obs.detail or obs.value, 110), settings.show_ip),
                }
            )
        if items:
            obs_groups.append(
                {"visibility": vis, "label": VISIBILITY_ZH.get(vis, vis), "entries": items[:14]}
            )

    history_rows = history_runs or []
    scores = [
        row["score"] for row in reversed(history_rows) if row.get("score") is not None
    ]
    if not scores and report.score is not None:
        scores = [report.score]
    def _row_time(row: dict[str, Any]) -> str:
        value = row.get("started_at")
        if isinstance(value, str):
            try:
                return _fmt_time(datetime.fromisoformat(value.replace("Z", "+00:00")))
            except ValueError:
                return value
        return _fmt_time(value)

    history_items = [
        {
            "time": _row_time(row),
            "verdict": row.get("verdict") or "—",
            "score": row.get("score"),
            "country": row.get("country") or "—",
            "ip": row.get("ip_masked") or "—",
        }
        for row in history_rows[:8]
    ]

    drift = [
        {
            "label": item.label,
            "previous": _clean(item.previous or "—", settings.show_ip),
            "current": _clean(item.current or "—", settings.show_ip),
        }
        for item in report.drift
        if item.changed
    ]

    account = None
    if report.account:
        account = {
            "state": report.account.state,
            "plan": report.account.plan,
            "organization": report.account.organization,
            "chat_capable": report.account.chat_capable,
            "detail": _clean(report.account.detail, settings.show_ip),
        }

    region_obs = report.observations.get("official.region_gate")
    region_value = region_obs.value if region_obs and isinstance(region_obs.value, dict) else {}
    region_available = region_value.get("available")
    gate_value = "OK" if region_available is True else ("BLOCKED" if region_available is False else "UNKNOWN")
    if (
        region_available is True
        and report.regions
        and env.country_code
        and env.country_code not in report.regions.codes
    ):
        gate_value = "MISMATCH"
    gate_hint = region_value.get("error_code") or (report.regions.effective if report.regions else "—") or "—"

    stats = [
        {
            "label": "出口",
            "value": ip or "—",
            "hint": f"{env.country_code or '?'} · {env.asn or '—'}",
        },
        {
            "label": "地区闸门",
            "value": gate_value,
            "hint": _clean(str(gate_hint), settings.show_ip),
        },
        {
            "label": "账号",
            "value": (account or {}).get("state", "unverified").upper(),
            "hint": (account or {}).get("plan") or ("参考模式" if account is None else "未提供套餐"),
        },
        {
            "label": "覆盖率",
            "value": f"{report.coverage * 100:.0f}%",
            "hint": f"置信度 {report.confidence.value}",
        },
    ]

    return {
        "run_id": report.run_id,
        "app_version": report.app_version,
        "rules_version": report.rules_version,
        "generated_at": _fmt_time(report.finished_at),
        "verdict": {
            "code": str(report.verdict.code),
            "title": report.verdict.title,
            "headline": report.verdict.headline,
            "reason": _clean(report.verdict.reason, settings.show_ip),
            "account_note": _clean(report.verdict.account_note, settings.show_ip),
            "confidence": str(report.verdict.confidence),
            "can_start": report.verdict.can_start,
            "color": color,
            "gate": report.verdict.gate,
        },
        "score": report.score,
        "score_display": "—" if report.score is None else f"{report.score:.0f}",
        "gauge_circumference": round(2 * math.pi * 64, 2),
        "gauge_offset": round((2 * math.pi * 64) * (1 - (report.score or 0) / 100), 2)
        if report.score is not None
        else round(2 * math.pi * 64, 2),
        "gauge_empty": report.score is None,
        "level": report.level,
        "level_zh": LEVEL_ZH.get(report.level, report.level),
        "score_basis": _score_basis_text(report),
        "coverage_pct": round(report.coverage * 100),
        "confidence": str(report.confidence),
        "environment": {
            "ip": ip,
            "ip_masked": env.ip_masked,
            "full_ip": env.ip if settings.show_ip else None,
            "country": env.country,
            "country_code": env.country_code,
            "city": env.city,
            "asn": env.asn,
            "org": env.org,
            "timezone": env.timezone,
            "locale": env.locale,
            "browser": env.browser,
            "os": env.os,
            "fingerprint": env.fingerprint,
        },
        "stats": stats,
        "radar": radar,
        "categories": categories,
        "findings": findings,
        "fixes": report.verdict.top_fixes,
        "obs_groups": obs_groups,
        "history": {
            "baseline": report.history.is_baseline,
            "last_run_at": _fmt_time(report.history.last_run_at),
            "scores": scores,
            "runs": history_items,
            "drift": drift,
        },
        "account": account,
        "reference_mode": report.account is None,
        "sources": [
            {"name": s.name, "url": _clean(s.url, settings.show_ip), "kind": str(s.kind)}
            for s in report.sources
        ],
        "disclaimers": report.disclaimers,
        "errors": [_clean(error, settings.show_ip) for error in report.errors[:8]],
    }


def render_html(
    report: Report,
    path: Path,
    settings: Settings,
    history_runs: list[dict[str, Any]] | None = None,
) -> Path:
    view = build_view(report, settings, history_runs)
    root = Path(__file__).parent / "templates"
    env = Environment(
        loader=FileSystemLoader(str(root)),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = env.get_template("report.html.j2")
    view_json = json.dumps(view, ensure_ascii=False).replace("</", "<\\/")
    html = template.render(view=view, view_json=view_json)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return path
