"""Category scoring, coverage and confidence."""

from __future__ import annotations

from typing import Any

from claude_sentinel.models import (
    Category,
    CategoryScore,
    Confidence,
    Finding,
    Severity,
    Status,
)

CONF_ORDER = {Confidence.low: 0, Confidence.medium: 1, Confidence.high: 2}

#: Populated by the most recent ``score_findings`` call, so the pipeline can
#: persist how the number was derived without changing the return signature.
SCORE_BASIS: dict[str, Any] = {}


def min_confidence(*values: Confidence | None) -> Confidence:
    present = [v for v in values if v is not None]
    if not present:
        return Confidence.low
    return min(present, key=lambda v: CONF_ORDER[v])


def level_from_score(score: float | None, weights: dict[str, Any]) -> str:
    """Map a **safety** score (100 = clean) onto a risk level."""
    if score is None:
        return "unknown"
    bands = weights.get("bands", {})
    if score >= bands.get("safe", 86):
        return "low"
    if score >= bands.get("caution", 66):
        return "medium"
    if score >= bands.get("high_risk", 41):
        return "high"
    return "critical"


def score_findings(
    findings: list[Finding],
    weights: dict[str, Any],
) -> tuple[list[CategoryScore], float | None, str, float, Confidence]:
    categories: list[CategoryScore] = []
    weighted_sum = 0.0
    included_weight = 0.0
    all_weight = 0.0
    coverage_weighted = 0.0

    for cat_key, cfg in weights.get("categories", {}).items():
        category = Category(cat_key)
        items = [
            f
            for f in findings
            if f.category == category and f.max_points > 0 and f.status != Status.info
        ]
        total = sum(f.max_points for f in items)
        if total <= 0:
            continue
        all_weight += float(cfg.get("weight", 0))

        evaluated = [f for f in items if f.status != Status.unknown]
        possible = sum(f.max_points for f in evaluated)
        earned = sum(f.points for f in evaluated)
        coverage = possible / total if total else 0.0
        # `earned` accumulates risk points, so safety is its complement.
        score = (100.0 - earned / possible * 100.0) if possible > 0 else None
        # A category that contains a decisive finding must not read safe just
        # because its other rules passed. Apply the same ceiling per category,
        # so "稳定性 70" can never hide a critical runtime_split inside it.
        if score is not None:
            category_cap = _severity_ceiling(evaluated)
            if category_cap is not None:
                score = min(score, category_cap[0])

        categories.append(
            CategoryScore(
                category=category,
                label=cfg.get("label", cat_key),
                weight=float(cfg.get("weight", 0)),
                earned=round(earned, 2),
                possible=round(possible, 2),
                total_possible=round(total, 2),
                score=round(score, 1) if score is not None else None,
                coverage=round(coverage, 3),
            )
        )

        if score is not None and coverage > 0:
            # Scale a category's weight by how much of it was actually measured
            # instead of dropping it below a hard cliff. One flaky data source
            # used to zero out a whole weight-30 category, which then pushed
            # overall coverage under 60% and produced "无法判断" for reasons the
            # user could not act on. A partially-measured category still carries
            # evidence; it simply counts proportionally less.
            weight = float(cfg.get("weight", 0))
            weighted_sum += score * weight * coverage
            included_weight += weight * coverage
            coverage_weighted += coverage * weight

    overall = weighted_sum / included_weight if included_weight > 0 else None
    overall_coverage = coverage_weighted / all_weight if all_weight > 0 else 0.0

    # A single serious finding must not be averaged away by the many rules that
    # passed. On a safety scale that means a *ceiling*: one decisive problem
    # caps how safe the environment can look, no matter how tidy the rest is.
    cap_info = _severity_ceiling(findings)
    cap = cap_info[0] if cap_info else None
    averaged = overall
    if cap is not None:
        overall = cap if overall is None else min(overall, cap)

    if overall is not None:
        overall = round(overall, 1)
    basis = {
        "averaged": round(averaged, 1) if averaged is not None else None,
        "cap": round(cap, 1) if cap is not None else None,
        "cap_rule": cap_info[1] if cap_info else None,
        "cap_severity": cap_info[2] if cap_info else None,
        "capped": bool(cap is not None and averaged is not None and cap < averaged),
        # kept for readers of older reports
        "scale": "safety",
    }
    SCORE_BASIS.clear()
    SCORE_BASIS.update(basis)
    level = level_from_score(overall, weights)

    if overall_coverage >= 0.8 and included_weight > 0:
        confidence = Confidence.high
    elif overall_coverage >= 0.5 and included_weight > 0:
        confidence = Confidence.medium
    else:
        confidence = Confidence.low

    return categories, overall, level, round(overall_coverage, 3), confidence

#: The ceiling a single finding of each severity imposes on the **safety**
#: score. A critical hit (Tor egress, disabled account, terminal bypassing the
#: proxy) caps the environment at "critical" on its own, regardless of how many
#: other checks pass.
SEVERITY_CEILING = {
    Severity.critical: 38.0,
    Severity.high: 60.0,
}


def _severity_ceiling(findings: list[Finding]) -> tuple[float, str, str] | None:
    """The highest safety score permitted by the worst finding present.

    Returns ``(ceiling, rule_id, severity)`` for the finding that set it.
    """
    worst: tuple[float, str, str] | None = None
    for finding in findings:
        if finding.status not in {Status.high, Status.warn}:
            continue
        if finding.max_points <= 0:
            continue
        base = SEVERITY_CEILING.get(finding.severity)
        if base is None:
            continue
        # Scale by how much of that rule's budget it earned, so a barely-tripped
        # high finding (10/40) does not cap as hard as a full miss.
        ratio = min(1.0, finding.points / finding.max_points) if finding.max_points else 0.0
        if ratio <= 0:
            continue
        # Full miss -> the base ceiling; light trip -> approaches 100.
        implied = 100.0 - (100.0 - base) * ratio
        if worst is None or implied < worst[0]:
            worst = (implied, finding.rule_id, str(finding.severity))
    return worst
