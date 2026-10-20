"""Optional deep behavior rules (aggregate counts only, no conversation content)."""

from __future__ import annotations

from claude_sentinel.models import (
    Category,
    FixType,
    Severity,
    Status,
    Visibility,
)
from claude_sentinel.rules.context import Context
from claude_sentinel.rules.registry import RuleMeta, RuleResult, rule
from claude_sentinel.rules.sources import LOCAL


def _behavior(ctx: Context) -> dict | None:
    return ctx.behavior if isinstance(ctx.behavior, dict) else None


@rule(
    RuleMeta(
        id="behavior.session_rate",
        title="会话/请求频率异常",
        category=Category.behavior,
        severity=Severity.high,
        max_points=40,
        fix="降低并发与自动化频率；不要在短时间内对同一账号做批量请求。",
        fix_type=FixType.none,
        visibility=Visibility.local,
        sources=[LOCAL],
    )
)
def session_rate(ctx: Context) -> RuleResult | None:
    data = _behavior(ctx)
    if data is None:
        return None
    rate = data.get("session_rate_per_min")
    if not isinstance(rate, (int, float)):
        return RuleResult(Status.unknown, "未计算出会话频率")
    if rate > 60:
        return RuleResult(Status.high, f"峰值约 {rate:.1f} 次/分钟")
    if rate > 30:
        return RuleResult(Status.warn, f"峰值约 {rate:.1f} 次/分钟")
    return RuleResult(Status.ok, f"峰值约 {rate:.1f} 次/分钟")


@rule(
    RuleMeta(
        id="behavior.cron",
        title="后台定时任务调用 Claude",
        category=Category.behavior,
        severity=Severity.medium,
        max_points=30,
        fix="检查 cron/launchd 中是否有自动调用；无人值守的批量任务更容易产生异常流量。",
        fix_type=FixType.none,
        visibility=Visibility.local,
        sources=[LOCAL],
    )
)
def cron(ctx: Context) -> RuleResult | None:
    data = _behavior(ctx)
    if data is None:
        return None
    jobs = data.get("cron_jobs")
    if not isinstance(jobs, int):
        return RuleResult(Status.unknown, "未检查后台任务")
    if jobs > 0:
        return RuleResult(Status.warn, f"发现 {jobs} 个包含 claude 的后台任务")
    return RuleResult(Status.ok, "未发现包含 claude 的后台任务")


@rule(
    RuleMeta(
        id="behavior.shell_batch",
        title="Shell 批量循环调用",
        category=Category.behavior,
        severity=Severity.high,
        max_points=30,
        fix="停止用 for/xargs/while 批量调用 claude；这类模式与滥用行为高度相似。",
        fix_type=FixType.none,
        visibility=Visibility.local,
        sources=[LOCAL],
    )
)
def shell_batch(ctx: Context) -> RuleResult | None:
    data = _behavior(ctx)
    if data is None:
        return None
    hits = data.get("shell_batch_hits")
    if not isinstance(hits, int):
        return RuleResult(Status.unknown, "未检查 shell 历史")
    if hits > 0:
        return RuleResult(Status.high, f"shell 历史中发现 {hits} 处批量调用痕迹")
    return RuleResult(Status.ok, "未发现批量调用痕迹")


@rule(
    RuleMeta(
        id="behavior.not_checked",
        title="行为维度未检查",
        category=Category.behavior,
        severity=Severity.info,
        max_points=0,
        fix="如需行为维度，运行 sentinel --deep；该模式只统计聚合计数，不读取对话内容。",
        fix_type=FixType.none,
        visibility=Visibility.local,
        sources=[LOCAL],
    )
)
def not_checked(ctx: Context) -> RuleResult | None:
    if _behavior(ctx) is None:
        return RuleResult(Status.info, "未启用 deep 模式")
    return None
