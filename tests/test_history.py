from __future__ import annotations

from pathlib import Path

from claude_sentinel.history import HistoryStore
from claude_sentinel.models import EnvironmentSummary
from tests.conftest import make_report


def test_save_summary_and_clear(tmp_path: Path):
    store = HistoryStore(tmp_path / "h.db")
    report = make_report(environment=EnvironmentSummary(ip="203.0.113.9", ip_masked="203.0.*.*", country_code="US", asn="AS111", timezone="America/Los_Angeles"))
    store.save(report)
    summary = store.summary()
    assert summary.is_baseline is False
    assert summary.runs == 1
    assert summary.last_country == "US"
    assert store.last()["score"] == 20.0
    store.clear()
    assert store.last() is None


def test_drift(tmp_path):
    store = HistoryStore(tmp_path / "h.db")
    first = make_report(environment=EnvironmentSummary(ip="203.0.113.9", ip_masked="203.0.*.*", country_code="US", asn="AS111", timezone="America/Los_Angeles"))
    store.save(first)
    last = store.last()
    current = {
        "ip": "198.51.100.7",
        "country": "JP",
        "asn": "AS999",
        "timezone": "Asia/Tokyo",
        "browser": "Safari",
        "fingerprint": "abc123",
        "account_state": "unknown",
        "verdict": "可以",
        "score": 30.0,
    }
    drift = store.compute_drift(current, last)
    changed = {d.field for d in drift if d.changed}
    assert {"ip", "country", "asn", "timezone"} <= changed
    assert "fingerprint" not in changed


def test_prune_does_not_crash(tmp_path: Path):
    store = HistoryStore(tmp_path / "h.db")
    store.save(make_report())
    store.prune(keep=1, days=1)
    assert store.last() is not None


# ------------------------------------------------- score-scale migration
def test_new_rows_are_tagged_as_safety(tmp_path: Path):
    store = HistoryStore(tmp_path / "h.db")
    report = make_report()
    report.score = 38.0
    store.save(report)
    row = store.last()
    assert row["score"] == 38.0
    assert row["score_scale"] == "safety"


def test_legacy_risk_scores_are_inverted_once(tmp_path: Path):
    """A database written before the safety scale must not be misread.

    Old "9" meant nearly clean; under the new meaning it would read as
    nearly worst. The migration converts and tags it exactly once.
    """
    import json
    import sqlite3

    db = tmp_path / "legacy.db"
    conn = sqlite3.connect(db)
    conn.executescript(
        """
        CREATE TABLE runs (
            id TEXT PRIMARY KEY, started_at TEXT NOT NULL, app_version TEXT NOT NULL,
            rules_version TEXT NOT NULL, verdict TEXT NOT NULL, score REAL, coverage REAL,
            country TEXT, ip TEXT, ip_masked TEXT, asn TEXT, timezone TEXT, locale TEXT,
            browser TEXT, fingerprint TEXT, account_state TEXT, report_json TEXT NOT NULL
        );
        CREATE TABLE findings (
            run_id TEXT NOT NULL, rule_id TEXT NOT NULL, severity TEXT NOT NULL,
            points REAL NOT NULL, evidence TEXT, PRIMARY KEY (run_id, rule_id)
        );
        """
    )
    conn.execute(
        "INSERT INTO runs VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            "old1", "2026-10-20T01:00:00+00:00", "0.6.0", "2", "可以发起对话",
            9.0, 0.86, "SG", "45.129.1.1", "45.129.*.*", "AS1",
            "Asia/Shanghai", "en-US", "Safari", "fp", "unknown",
            json.dumps({"score": 9.0, "run_id": "old1"}),
        ),
    )
    conn.commit()
    conn.close()

    store = HistoryStore(db)
    row = store.last()
    assert row["score"] == 91.0
    assert row["score_scale"] == "safety"
    assert json.loads(row["report_json"])["score"] == 91.0

    # Re-opening must not invert again.
    reopened = HistoryStore(db).last()
    assert reopened["score"] == 91.0


def test_migration_handles_a_null_score(tmp_path: Path):
    import sqlite3

    db = tmp_path / "legacy_null.db"
    conn = sqlite3.connect(db)
    conn.executescript(
        """
        CREATE TABLE runs (
            id TEXT PRIMARY KEY, started_at TEXT NOT NULL, app_version TEXT NOT NULL,
            rules_version TEXT NOT NULL, verdict TEXT NOT NULL, score REAL, coverage REAL,
            country TEXT, ip TEXT, ip_masked TEXT, asn TEXT, timezone TEXT, locale TEXT,
            browser TEXT, fingerprint TEXT, account_state TEXT, report_json TEXT NOT NULL
        );
        CREATE TABLE findings (
            run_id TEXT NOT NULL, rule_id TEXT NOT NULL, severity TEXT NOT NULL,
            points REAL NOT NULL, evidence TEXT, PRIMARY KEY (run_id, rule_id)
        );
        """
    )
    conn.execute(
        "INSERT INTO runs VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ("g1", "2026-10-20T01:00:00+00:00", "0.6.0", "2", "不可发起对话",
         None, 0.3, "CN", None, None, None, None, None, None, None, None, "{}"),
    )
    conn.commit()
    conn.close()

    row = HistoryStore(db).last()
    assert row["score"] is None
    # No score to invert, but the tag still moves so the column never mixes
    # two meanings.
    assert row["score_scale"] == "safety"


def test_migrated_scores_land_in_the_band_their_verdict_implied(tmp_path: Path):
    """The inversion must be self-consistent with the stored verdicts.

    A run stored as "可以发起对话" at risk 12.8 becomes safety 87.2, which must
    still read as ready (>= 86). If the inversion or the thresholds were off by
    any amount, this test catches it.
    """
    import json
    import sqlite3

    from claude_sentinel.config import load_weights
    from claude_sentinel.scoring import level_from_score

    db = tmp_path / "bands.db"
    conn = sqlite3.connect(db)
    conn.executescript(
        """
        CREATE TABLE runs (
            id TEXT PRIMARY KEY, started_at TEXT NOT NULL, app_version TEXT NOT NULL,
            rules_version TEXT NOT NULL, verdict TEXT NOT NULL, score REAL, coverage REAL,
            country TEXT, ip TEXT, ip_masked TEXT, asn TEXT, timezone TEXT, locale TEXT,
            browser TEXT, fingerprint TEXT, account_text TEXT, report_json TEXT NOT NULL
        );
        """
    )
    # (old risk score, verdict text, expected safety level)
    cases = [
        ("r1", 9.0, "可以发起对话", "low"),
        ("r2", 12.8, "可以发起对话", "low"),
        ("r3", 30.0, "可以，但建议先处理", "medium"),
        ("r4", 50.0, "谨慎发起", "high"),
        ("r5", 62.0, "不建议发起", "critical"),
    ]
    for run_id, risk, verdict, _level in cases:
        conn.execute(
            "INSERT INTO runs VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (run_id, "2026-10-20T01:00:00+00:00", "0.6.0", "2", verdict,
             risk, 0.9, "SG", None, None, None, None, None, None, None, None,
             json.dumps({"score": risk})),
        )
    conn.commit()
    conn.close()

    store = HistoryStore(db)
    weights = load_weights()
    for run_id, risk, verdict, expected_level in cases:
        row = next(r for r in store.recent(10) if r["id"] == run_id)
        assert row["score"] == round(100.0 - risk, 1), f"{run_id} not inverted"
        assert level_from_score(row["score"], weights) == expected_level, (
            f"{run_id}: safety {row['score']} implied by '{verdict}' "
            f"should be {expected_level}"
        )
