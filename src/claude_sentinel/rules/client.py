"""Claude Code client posture rules: endpoint override and auth shape."""

from __future__ import annotations

from claude_sentinel.collectors.claude_code import is_old_marker_version
from claude_sentinel.models import (
    Category,
    FixType,
    Severity,
    Status,
    Visibility,
)
from claude_sentinel.rules.context import Context
from claude_sentinel.rules.registry import RuleMeta, RuleResult, rule
from claude_sentinel.rules.sources import CLIENT


@rule(
    RuleMeta(
        id="client.base_url",
        title="Claude Code 使用第三方中转",
        category=Category.client,
        severity=Severity.high,
        max_points=50,
        fix="改用官方端点或官方支持的云厂商。第三方中转会让请求经过非官方服务，并可能引入额外的账号归因风险。",
        fix_type=FixType.client,
        visibility=Visibility.server,
        sources=[CLIENT],
    )
)
def base_url(ctx: Context) -> RuleResult | None:
    if ctx.client is None:
        return None
    kind = ctx.client.base_url_kind
    if kind == "third_party":
        return RuleResult(
            Status.high,
            f"ANTHROPIC_BASE_URL 指向第三方：{ctx.client.relay_hint or '?'}",
            details={"host": ctx.client.relay_hint},
        )
    if kind == "invalid":
        return RuleResult(Status.warn, "ANTHROPIC_BASE_URL 不是合法 URL")
    if kind == "official":
        return RuleResult(Status.ok, "使用官方 API 端点")
    return RuleResult(Status.ok, "未设置 ANTHROPIC_BASE_URL（使用默认官方端点）")


@rule(
    RuleMeta(
        id="client.old_marker",
        title="旧版 Claude Code + 第三方中转",
        category=Category.client,
        severity=Severity.medium,
        max_points=20,
        fix="升级 Claude Code；2026-06 的逆向分析显示 2.1.91–2.1.196 会基于中转地址/时区在提示词中做标记，2.1.197 已移除。",
        fix_type=FixType.client,
        visibility=Visibility.server,
        sources=[CLIENT],
    )
)
def old_marker(ctx: Context) -> RuleResult | None:
    if ctx.client is None or not ctx.client.version:
        return None
    if not is_old_marker_version(ctx.client.version):
        return RuleResult(Status.ok, f"版本 {ctx.client.version} 不在标记版本区间")
    if ctx.client.base_url_kind == "third_party":
        return RuleResult(
            Status.warn,
            f"版本 {ctx.client.version} 属于 2.1.91–2.1.196 区间，且使用第三方中转",
        )
    return RuleResult(
        Status.ok,
        f"版本 {ctx.client.version} 属于旧区间，但未使用第三方中转",
    )


@rule(
    RuleMeta(
        id="client.mixed_auth",
        title="OAuth 与 API key 混用",
        category=Category.client,
        severity=Severity.medium,
        max_points=30,
        fix="只保留一种认证方式；混用会让账号/组织归因变得混乱。",
        fix_type=FixType.client,
        visibility=Visibility.server,
        sources=[CLIENT],
    )
)
def mixed_auth(ctx: Context) -> RuleResult | None:
    if ctx.client is None:
        return None
    modes = set(ctx.client.auth_modes)
    if len(modes) > 1:
        return RuleResult(Status.warn, "同时存在：" + ", ".join(sorted(modes)))
    if modes:
        return RuleResult(Status.ok, "只有一种认证形态：" + ", ".join(sorted(modes)))
    return RuleResult(Status.ok, "未发现显式认证环境变量")


@rule(
    RuleMeta(
        id="client.settings_override",
        title="Claude Code 配置覆盖",
        category=Category.client,
        severity=Severity.low,
        max_points=10,
        fix="检查 settings.json 中的 apiKeyHelper/forceLoginMethod/env 覆盖；只保留你确实需要的项。",
        fix_type=FixType.client,
        visibility=Visibility.local,
        sources=[CLIENT],
    )
)
def settings_override(ctx: Context) -> RuleResult | None:
    if ctx.client is None or not ctx.client.settings_present:
        return None
    risky = [
        key
        for key in ctx.client.settings_keys
        if key in {"apiKeyHelper", "forceLoginMethod"}
    ]
    if risky:
        return RuleResult(Status.warn, "配置覆盖：" + ", ".join(risky[:8]))
    return RuleResult(Status.ok, "未发现高风险配置覆盖")


@rule(
    RuleMeta(
        id="client.not_installed",
        title="未检测到 Claude Code",
        category=Category.client,
        severity=Severity.info,
        max_points=0,
        fix="如果你只使用网页版 Claude，可忽略此项。",
        fix_type=FixType.none,
        visibility=Visibility.local,
        sources=[CLIENT],
    )
)
def not_installed(ctx: Context) -> RuleResult | None:
    if ctx.client is None:
        return RuleResult(Status.info, "无 Claude Code 数据")
    if not ctx.client.installed:
        return RuleResult(Status.info, "未安装 Claude Code")
    return None
