from __future__ import annotations

from claude_sentinel.models import (
    Category,
    Confidence,
    Finding,
    Severity,
    Status,
)
from claude_sentinel.scoring import level_from_score, min_confidence, score_findings

# Kept small and deterministic, but the band keys must match the real config:
# `level_from_score` falls back to defaults when they are missing, which would
# let a typo here pass silently.
WEIGHTS = {
    "categories": {
        "ip": {"weight": 30, "label": "网络出口与信誉"},
        "identity": {"weight": 20, "label": "本地身份一致性"},
        "client": {"weight": 20, "label": "客户端与中转"},
        "stability": {"weight": 12, "label": "出口稳定性"},
    },
    "bands": {"safe": 86, "caution": 66, "high_risk": 41},
}


def test_fixture_bands_match_production_config():
    from claude_sentinel.config import load_weights

    real = load_weights()["bands"]
    assert set(WEIGHTS["bands"]) == set(real), "band keys drifted from weights.yaml"
    for key, value in WEIGHTS["bands"].items():
        assert value == real[key], f"band {key} drifted from weights.yaml"


def finding(
    rule_id: str,
    category: Category,
    status: Status,
    points: float,
    max_points: float,
    severity: Severity = Severity.high,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=rule_id,
        category=category,
        severity=severity,
        status=status,
        points=points,
        max_points=max_points,
        evidence="e",
        fix="f",
        confidence=Confidence.medium,
    )


def test_category_score_and_coverage():
    findings = [
        finding("a", Category.ip, Status.high, 30, 30),
        finding("b", Category.ip, Status.ok, 0, 20),
        finding("c", Category.ip, Status.unknown, 0, 10),
        finding("d", Category.identity, Status.ok, 0, 40),
    ]
    categories, overall, level, coverage, confidence = score_findings(findings, WEIGHTS)
    ip = next(c for c in categories if c.category == Category.ip)
    assert ip.possible == 50
    assert ip.total_possible == 60
    # `score` is a safety value now: rule "a" earned 30 of 50 possible risk
    # points, so this category is 40% safe.
    assert ip.score == 40.0
    assert round(ip.coverage, 3) == round(50 / 60, 3)
    # Categories are weighted *by* their measured coverage, so a partly
    # measured category counts proportionally instead of being dropped at a
    # 0.5 cliff (which used to turn one flaky source into "无法判断").
    # The weighted average is then capped by the worst finding: rule "a" is a
    # high severity 30/30 hit, so the environment cannot read safer than 60 --
    # otherwise one decisive problem would be averaged away by green neighbours.
    assert overall == 60.0
    assert level == "high"
    assert confidence == Confidence.high


def test_low_coverage_removes_category_from_overall():
    findings = [
        finding("a", Category.ip, Status.unknown, 0, 30),
        finding("b", Category.identity, Status.ok, 0, 40),
    ]
    categories, overall, level, coverage, confidence = score_findings(findings, WEIGHTS)
    # Only identity was measurable and it was clean -> 100 safety, low coverage.
    assert overall == 100.0
    assert coverage < 0.5
    assert confidence == Confidence.low


def test_bands():
    """Safety scale: 100 is cleanest, 0 is worst."""
    assert level_from_score(None, WEIGHTS) == "unknown"
    assert level_from_score(100, WEIGHTS) == "low"
    assert level_from_score(86, WEIGHTS) == "low"
    assert level_from_score(85, WEIGHTS) == "medium"
    assert level_from_score(66, WEIGHTS) == "medium"
    assert level_from_score(65, WEIGHTS) == "high"
    assert level_from_score(41, WEIGHTS) == "high"
    assert level_from_score(40, WEIGHTS) == "critical"
    assert level_from_score(0, WEIGHTS) == "critical"


def test_min_confidence():
    assert min_confidence(Confidence.high, Confidence.low) == Confidence.low
    assert min_confidence(Confidence.high, Confidence.medium) == Confidence.medium
    assert min_confidence(Confidence.high, None) == Confidence.high


# ------------------------------------------------------- severity floors
def _sev(rid, cat, status, points, max_points, severity):
    return Finding(
        rule_id=rid,
        title=rid,
        category=cat,
        severity=severity,
        status=status,
        points=points,
        max_points=max_points,
        evidence="e",
        fix="f",
    )


def _green_neighbours():
    """A tidy environment, so any score comes from the finding under test."""
    return [
        _sev("ip.a", Category.ip, Status.ok, 0, 30, Severity.high),
        _sev("ip.b", Category.ip, Status.ok, 0, 30, Severity.high),
        _sev("ip.c", Category.ip, Status.ok, 0, 30, Severity.high),
        _sev("st.a", Category.stability, Status.ok, 0, 40, Severity.high),
        _sev("cl.a", Category.client, Status.ok, 0, 50, Severity.high),
    ]


def test_clean_environment_scores_full_marks():
    """Safety scale: nothing wrong means 100."""
    _, score, level, _, _ = score_findings(_green_neighbours(), WEIGHTS)
    assert score == 100.0
    assert level == "low"


def test_one_full_high_finding_caps_the_safety_score():
    """A 40/40 hit must not be averaged away by green neighbours.

    On the safety scale that means the environment cannot read safer than the
    ceiling implied by that finding (60 for a fully-hit high rule).
    """
    findings = _green_neighbours() + [
        _sev("id.tz", Category.identity, Status.high, 40, 40, Severity.high)
    ]
    _, score, level, _, _ = score_findings(findings, WEIGHTS)
    assert score <= 60.0
    assert level in {"high", "critical"}


def test_a_critical_finding_reaches_the_worst_band_on_its_own():
    findings = _green_neighbours() + [
        _sev("ip.tor", Category.ip, Status.high, 20, 20, Severity.critical)
    ]
    _, score, level, _, _ = score_findings(findings, WEIGHTS)
    assert score <= 38.0
    assert level == "critical"


def test_cap_scales_with_how_much_of_the_rule_was_earned():
    """A barely-tripped high finding must not cap as hard as a full miss."""
    mild = _green_neighbours() + [
        _sev("id.dns", Category.identity, Status.warn, 6, 30, Severity.high)
    ]
    severe = _green_neighbours() + [
        _sev("id.dns", Category.identity, Status.high, 30, 30, Severity.high)
    ]
    _, mild_score, _, _, _ = score_findings(mild, WEIGHTS)
    _, severe_score, _, _, _ = score_findings(severe, WEIGHTS)
    # Higher is safer, so the mild case must score higher.
    assert mild_score > severe_score


def test_cap_ignores_unknown_and_info_findings():
    findings = _green_neighbours() + [
        _sev("id.x", Category.identity, Status.unknown, 0, 40, Severity.critical),
        _sev("id.y", Category.identity, Status.info, 0, 0, Severity.critical),
    ]
    _, score, level, _, _ = score_findings(findings, WEIGHTS)
    assert score == 100.0
    assert level == "low"


def test_score_basis_records_the_cap():
    import claude_sentinel.scoring as scoring_mod

    findings = _green_neighbours() + [
        _sev("st.split", Category.stability, Status.high, 50, 50, Severity.critical)
    ]
    score_findings(findings, WEIGHTS)
    basis = dict(scoring_mod.SCORE_BASIS)
    assert basis["scale"] == "safety"
    assert basis["capped"] is True
    assert basis["cap_rule"] == "st.split"
    assert basis["cap_severity"] == "critical"
    assert basis["averaged"] > basis["cap"]


def test_category_score_is_capped_by_its_own_findings():
    """A clean-looking category must not hide a decisive finding inside it.

    Without this, `stability` averaged out to 70 while containing a critical
    runtime_split, so the axis read "mostly fine" on screen.
    """
    findings = [
        _sev("st.split", Category.stability, Status.high, 50, 50, Severity.critical),
        _sev("st.dual", Category.stability, Status.ok, 0, 40, Severity.high),
        _sev("st.churn", Category.stability, Status.ok, 0, 30, Severity.high),
        _sev("ip.a", Category.ip, Status.ok, 0, 30, Severity.high),
    ]
    categories, _, _, _, _ = score_findings(findings, WEIGHTS)
    stability = next(c for c in categories if c.category == Category.stability)
    ip = next(c for c in categories if c.category == Category.ip)
    assert stability.score is not None and stability.score <= 38.0
    # An axis with nothing wrong still reads clean.
    assert ip.score == 100.0


def test_category_earned_points_stay_truthful_after_the_cap():
    """The cap changes the displayed safety, not the underlying risk points."""
    findings = [
        _sev("st.split", Category.stability, Status.high, 50, 50, Severity.critical),
        _sev("st.dual", Category.stability, Status.ok, 0, 40, Severity.high),
    ]
    categories, _, _, _, _ = score_findings(findings, WEIGHTS)
    stability = next(c for c in categories if c.category == Category.stability)
    assert stability.earned == 50.0
    assert stability.possible == 90.0
