"""Shared test fixtures and tiny builders."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from claude_sentinel.config import Settings
from claude_sentinel.models import (
    Confidence,
    EnvironmentSummary,
    HistorySummary,
    IpConsensus,
    Report,
    Verdict,
    VerdictCode,
)
from claude_sentinel.rules.context import Context, GateInfo


def make_report(**overrides) -> Report:
    now = datetime.now(timezone.utc)
    verdict = Verdict(
        code=VerdictCode.caution,
        title="有可改进项",
        headline="可以，但建议先处理",
        reason="环境基本可用，但存在若干可改进项。",
        can_start=True,
        account_note="账号层：未验证",
        confidence=Confidence.medium,
    )
    report = Report(
        run_id="testrun",
        started_at=now,
        finished_at=now,
        app_version="0.2.0",
        rules_version="1",
        verdict=verdict,
        score=20.0,
        level="medium",
        coverage=0.8,
        confidence=Confidence.medium,
        environment=EnvironmentSummary(
            ip="203.0.113.9",
            ip_masked="203.0.*.*",
            country="United States",
            country_code="US",
            asn="AS12345",
            timezone="Asia/Shanghai",
            locale="zh-CN",
            browser="Safari",
            fingerprint="abc123",
        ),
    )
    for key, value in overrides.items():
        setattr(report, key, value)
    return report


def make_context(tmp_path: Path, **overrides) -> Context:
    ctx = Context(
        settings=Settings(home=tmp_path),
        observations={},
        ip=IpConsensus(ip="203.0.113.9", country_code="US", country="United States"),
        ipv4=None,
        ipv6=None,
        rdap=None,
        regions=None,
        status=None,
        account=None,
        profile=None,
        client=None,
        local=None,
        browser=None,
        behavior=None,
        history=HistorySummary(),
        gate=GateInfo(),
    )
    for key, value in overrides.items():
        setattr(ctx, key, value)
    return ctx
