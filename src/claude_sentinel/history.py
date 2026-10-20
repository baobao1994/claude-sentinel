"""SQLite-backed environment memory and drift comparison."""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from claude_sentinel.models import (
    Drift,
    HistorySummary,
    Report,
    Severity,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    started_at TEXT NOT NULL,
    app_version TEXT NOT NULL,
    rules_version TEXT NOT NULL,
    verdict TEXT NOT NULL,
    score REAL,
    coverage REAL,
    country TEXT,
    ip TEXT,
    ip_masked TEXT,
    asn TEXT,
    timezone TEXT,
    locale TEXT,
    browser TEXT,
    fingerprint TEXT,
    account_state TEXT,
    score_scale TEXT NOT NULL DEFAULT 'risk',
    report_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    run_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    points REAL NOT NULL,
    evidence TEXT,
    PRIMARY KEY (run_id, rule_id)
);
CREATE INDEX IF NOT EXISTS idx_runs_started ON runs(started_at);
"""


def _parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except ValueError:
        return None


class HistoryStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _init(self) -> None:
        with self._connect() as conn:
            conn.executescript(SCHEMA)
            self._migrate(conn)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    @staticmethod
    def _migrate(conn: sqlite3.Connection) -> None:
        """Bring older databases onto the current schema and score scale.

        Scores used to be risk (0 = clean); they are now safety (100 = clean).
        Historical rows are converted once, and tagged, so a chart never mixes
        the two scales. Without this an old "9" would read as "very unsafe"
        under the new meaning.
        """
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(runs)")}
        if "score_scale" not in columns:
            conn.execute(
                "ALTER TABLE runs ADD COLUMN score_scale TEXT NOT NULL DEFAULT 'risk'"
            )
        # Rows with no score have nothing to convert, but still need the tag so
        # the column never mixes meanings.
        conn.execute(
            "UPDATE runs SET score_scale = 'safety' "
            "WHERE score_scale = 'risk' AND score IS NULL"
        )
        rows = conn.execute(
            "SELECT id, score FROM runs WHERE score_scale = 'risk' AND score IS NOT NULL"
        ).fetchall()
        for row in rows:
            inverted = max(0.0, min(100.0, 100.0 - float(row["score"])))
            conn.execute(
                "UPDATE runs SET score = ?, score_scale = 'safety' WHERE id = ?",
                (round(inverted, 1), row["id"]),
            )
        # Also rewrite the embedded report JSON, which drives /api/latest and
        # the reopen-an-old-report path.
        reports = conn.execute(
            "SELECT id, report_json FROM runs WHERE score_scale = 'safety' AND report_json IS NOT NULL"
        ).fetchall()
        for row in reports:
            try:
                payload = json.loads(row["report_json"])
            except (TypeError, ValueError):
                continue
            score = payload.get("score")
            if isinstance(score, (int, float)):
                payload["score"] = round(max(0.0, min(100.0, 100.0 - float(score))), 1)
                payload["score_scale"] = "safety"
                conn.execute(
                    "UPDATE runs SET report_json = ? WHERE id = ?",
                    (json.dumps(payload, ensure_ascii=False), row["id"]),
                )

    def save(self, report: Report) -> None:
        env = report.environment
        payload = json.dumps(report.model_dump(mode="json"), ensure_ascii=False)
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO runs (
                    id, started_at, app_version, rules_version, verdict, score,
                    coverage, country, ip, ip_masked, asn, timezone, locale,
                    browser, fingerprint, account_state, score_scale, report_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    report.run_id,
                    report.started_at.isoformat(),
                    report.app_version,
                    report.rules_version,
                    report.verdict.headline,
                    report.score,
                    report.coverage,
                    env.country_code,
                    env.ip,
                    env.ip_masked,
                    env.asn,
                    env.timezone,
                    env.locale,
                    env.browser,
                    env.fingerprint,
                    env.account_state,
                    "safety",
                    payload,
                ),
            )
            conn.execute("DELETE FROM findings WHERE run_id = ?", (report.run_id,))
            for finding in report.findings:
                conn.execute(
                    "INSERT OR REPLACE INTO findings (run_id, rule_id, severity, points, evidence) VALUES (?, ?, ?, ?, ?)",
                    (
                        report.run_id,
                        finding.rule_id,
                        str(finding.severity),
                        finding.points,
                        finding.evidence,
                    ),
                )

    def last(self) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM runs ORDER BY started_at DESC LIMIT 1"
            ).fetchone()
        return dict(row) if row else None

    def recent(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM runs ORDER BY started_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def summary(self) -> HistorySummary:
        rows = self.recent(500)
        if not rows:
            return HistorySummary(is_baseline=True)
        last = rows[0]
        now = datetime.now(timezone.utc)
        parsed = [(r, _parse_ts(r.get("started_at"))) for r in rows]
        last24 = [r for r, ts in parsed if ts and ts >= now - timedelta(hours=24)]
        last7 = [r for r, ts in parsed if ts and ts >= now - timedelta(days=7)]

        jumps = 0
        ordered = sorted(
            [(ts, r) for r, ts in parsed if ts is not None],
            key=lambda item: item[0],
        )
        for i in range(1, len(ordered)):
            prev_ts, prev = ordered[i - 1]
            cur_ts, cur = ordered[i]
            if (
                prev.get("country")
                and cur.get("country")
                and prev["country"] != cur["country"]
                and (cur_ts - prev_ts) <= timedelta(hours=1)
            ):
                jumps += 1

        return HistorySummary(
            is_baseline=False,
            runs=len(rows),
            last_run_at=_parse_ts(last.get("started_at")),
            last_verdict=last.get("verdict"),
            last_score=last.get("score"),
            last_ip=last.get("ip"),
            last_ip_masked=last.get("ip_masked"),
            last_country=last.get("country"),
            last_asn=last.get("asn"),
            last_timezone=last.get("timezone"),
            last_browser=last.get("browser"),
            distinct_ips_24h=len({r.get("ip") for r in last24 if r.get("ip")}),
            distinct_asns_24h=len({r.get("asn") for r in last24 if r.get("asn")}),
            distinct_countries_24h=len({r.get("country") for r in last24 if r.get("country")}),
            distinct_ips_7d=len({r.get("ip") for r in last7 if r.get("ip")}),
            country_jumps_1h=jumps,
        )

    def compute_drift(
        self, current: dict[str, Any], last: dict[str, Any] | None
    ) -> list[Drift]:
        if not last:
            return []
        fields = [
            ("ip", "出口 IP", Severity.medium),
            ("country", "出口国家", Severity.high),
            ("asn", "ASN", Severity.medium),
            ("timezone", "系统时区", Severity.high),
            ("browser", "浏览器", Severity.low),
            ("fingerprint", "设备指纹", Severity.medium),
            ("account_state", "账号状态", Severity.high),
            ("verdict", "结论", Severity.low),
            ("score", "安全分", Severity.low),
        ]
        drift: list[Drift] = []
        for key, label, severity in fields:
            prev = last.get(key)
            cur = current.get(key)
            prev_text = f"{prev:.0f}" if isinstance(prev, (int, float)) else (str(prev) if prev not in (None, "") else None)
            cur_text = f"{cur:.0f}" if isinstance(cur, (int, float)) else (str(cur) if cur not in (None, "") else None)
            changed = bool(prev_text and cur_text and prev_text != cur_text)
            drift.append(
                Drift(
                    field=key,
                    label=label,
                    previous=prev_text,
                    current=cur_text,
                    severity=severity,
                    changed=changed,
                )
            )
        return drift

    def prune(self, keep: int = 200, days: int = 180) -> int:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        with self._connect() as conn:
            conn.execute(
                """
                DELETE FROM runs WHERE id NOT IN (
                    SELECT id FROM runs ORDER BY started_at DESC LIMIT ?
                ) OR started_at < ?
                """,
                (keep, cutoff),
            )
            conn.execute(
                "DELETE FROM findings WHERE run_id NOT IN (SELECT id FROM runs)"
            )
        with self._connect() as conn:
            conn.execute("VACUUM")
        return 0

    def clear(self) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM findings")
            conn.execute("DELETE FROM runs")
        with self._connect() as conn:
            conn.execute("VACUUM")

    def load_report(self, run_id: str) -> Report | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT report_json FROM runs WHERE id = ?", (run_id,)
            ).fetchone()
        if not row:
            return None
        try:
            return Report.model_validate_json(row["report_json"])
        except Exception:
            return None
