from __future__ import annotations

from pathlib import Path

from claude_sentinel.models import (
    AccountState,
    Confidence,
    IpConsensus,
    RegionList,
    ServiceStatus,
    VerdictCode,
)
from claude_sentinel.rules.context import GateInfo
from claude_sentinel.verdict import build_verdict
from tests.conftest import make_context


def test_ready():
    ctx = make_context(Path("."))
    verdict = build_verdict(ctx, [], 95.0, "low", 0.9, Confidence.high)
    assert verdict.code == VerdictCode.ready
    assert verdict.can_start is True


def test_region_gate_blocks():
    ctx = make_context(Path("."), gate=GateInfo(region_available=False, region_error_code="region_unavailable"))
    verdict = build_verdict(ctx, [], 95.0, "low", 0.9, Confidence.high)
    assert verdict.code == VerdictCode.blocked_region
    assert verdict.can_start is False


def test_account_disabled_blocks_first():
    ctx = make_context(
        Path("."),
        account=AccountState(state="disabled"),
        gate=GateInfo(region_available=False),
    )
    verdict = build_verdict(ctx, [], 95.0, "low", 0.9, Confidence.high)
    assert verdict.code == VerdictCode.blocked_account


def test_service_outage_blocks():
    ctx = make_context(
        Path("."),
        status=ServiceStatus(indicator="major", relevant_ok=False),
    )
    verdict = build_verdict(ctx, [], 95.0, "low", 0.9, Confidence.high)
    assert verdict.code == VerdictCode.blocked_service


def test_clock_skew_blocks():
    ctx = make_context(Path("."), gate=GateInfo(clock_offset=400))
    verdict = build_verdict(ctx, [], 95.0, "low", 0.9, Confidence.high)
    assert verdict.code == VerdictCode.blocked_clock


def test_unknown_without_score():
    ctx = make_context(Path("."))
    verdict = build_verdict(ctx, [], None, "unknown", 0.2, Confidence.low)
    assert verdict.code == VerdictCode.unknown
    assert verdict.can_start is None


def test_bands():
    """Safety scale: >=86 ready, >=66 caution, >=41 high_caution, else stop."""
    ctx = make_context(Path("."))
    assert build_verdict(ctx, [], 90.0, "low", 0.9, Confidence.high).code == VerdictCode.ready
    assert build_verdict(ctx, [], 75.0, "medium", 0.9, Confidence.high).code == VerdictCode.caution
    assert build_verdict(ctx, [], 55.0, "high", 0.9, Confidence.high).code == VerdictCode.high_caution
    verdict = build_verdict(ctx, [], 20.0, "critical", 0.9, Confidence.high)
    assert verdict.code == VerdictCode.do_not_start
    assert verdict.can_start is False


def test_gate_ok_but_list_blocked_reason_is_explicit():
    ctx = make_context(
        Path("."),
        ip=IpConsensus(ip="203.0.113.9", country_code="JP"),
        regions=RegionList(codes={"US"}),
        gate=GateInfo(region_available=True),
    )
    verdict = build_verdict(ctx, [], 75.0, "medium", 0.9, Confidence.high)
    assert verdict.code == VerdictCode.blocked_region
    assert "官方区域闸门通过" in verdict.reason
    assert "JP" in verdict.reason


def test_account_region_block_blocks():
    ctx = make_context(
        Path("."),
        account=AccountState(state="region_blocked"),
        gate=GateInfo(region_available=True),
    )
    verdict = build_verdict(ctx, [], 10.0, "low", 0.9, Confidence.high)
    assert verdict.code == VerdictCode.blocked_region
    assert "账号接口" in verdict.reason
