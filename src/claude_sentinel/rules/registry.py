"""Tiny rule registry and evaluator.

Rules are plain Python functions, not a DSL: easier to read, test and audit.
Each rule declares its metadata (including sources) next to its predicate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from claude_sentinel.models import (
    Category,
    Confidence,
    Finding,
    FixType,
    Severity,
    Source,
    Status,
    Visibility,
)
from claude_sentinel.rules.context import Context


@dataclass
class RuleMeta:
    id: str
    title: str
    category: Category
    severity: Severity
    max_points: float
    fix: str
    fix_type: FixType
    visibility: Visibility
    sources: list[Source] = field(default_factory=list)
    description: str = ""
    confidence: Confidence = Confidence.medium


@dataclass
class RuleResult:
    status: Status
    evidence: str
    details: dict[str, Any] = field(default_factory=dict)
    points_override: float | None = None
    confidence: Confidence | None = None


RuleFunc = Callable[[Context], RuleResult | None]

RULES: list[tuple[RuleMeta, RuleFunc]] = []


def rule(meta: RuleMeta):
    def decorator(fn: RuleFunc) -> RuleFunc:
        RULES.append((meta, fn))
        return fn

    return decorator


def all_rules() -> list[tuple[RuleMeta, RuleFunc]]:
    return list(RULES)


MULTIPLIER = {
    Status.ok: 0.0,
    Status.info: 0.0,
    Status.warn: 0.6,
    Status.high: 1.0,
    Status.unknown: 0.0,
}


def evaluate(ctx: Context) -> list[Finding]:
    findings: list[Finding] = []
    for meta, fn in RULES:
        try:
            result = fn(ctx)
        except Exception as exc:  # noqa: BLE001 - one bad rule must not kill the scan
            result = RuleResult(
                Status.unknown,
                "规则执行失败",
                details={"error": str(exc)},
            )
        if result is None or result.status == Status.skipped:
            continue

        max_points = 0.0 if result.status == Status.info else meta.max_points
        points = (
            result.points_override
            if result.points_override is not None
            else max_points * MULTIPLIER.get(result.status, 0.0)
        )
        findings.append(
            Finding(
                rule_id=meta.id,
                title=meta.title,
                category=meta.category,
                severity=meta.severity,
                status=result.status,
                points=round(float(points), 2),
                max_points=float(max_points),
                evidence=result.evidence,
                fix=meta.fix,
                fix_type=meta.fix_type,
                visibility=meta.visibility,
                confidence=result.confidence or meta.confidence,
                sources=meta.sources,
                details=result.details,
            )
        )
    return findings
