"""Account-state and self-reported account-profile rules."""

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
from claude_sentinel.rules.sources import ACCOUNT, POLICY


@rule(
    RuleMeta(
        id="account.disabled",
        title="账号被停用",
        category=Category.account,
        severity=Severity.critical,
        max_points=0,
        fix="通过官方申诉入口处理；不要用新账号/新设备规避，可能扩大关联封禁。",
        fix_type=FixType.account,
        visibility=Visibility.server,
        sources=[ACCOUNT, POLICY],
    )
)
def disabled(ctx: Context) -> RuleResult | None:
    if ctx.account is None:
        return None
    if ctx.account.state == "disabled":
        return RuleResult(Status.high, ctx.account.detail or "账号状态为 disabled")
    if ctx.account.state == "active":
        return RuleResult(Status.ok, "账号状态 active")
    return None


@rule(
    RuleMeta(
        id="account.expired",
        title="登录会话已失效",
        category=Category.account,
        severity=Severity.medium,
        max_points=10,
        fix="重新登录即可；这不是封号。不要反复重试同一失效 Cookie。",
        fix_type=FixType.account,
        visibility=Visibility.server,
        sources=[ACCOUNT],
    )
)
def expired(ctx: Context) -> RuleResult | None:
    if ctx.account is None:
        return None
    if ctx.account.state == "expired":
        return RuleResult(Status.warn, ctx.account.detail or "会话已失效/需要重新登录")
    if ctx.account.state == "active":
        return RuleResult(Status.ok, "会话有效")
    return None


@rule(
    RuleMeta(
        id="account.no_chat",
        title="账号可能没有对话能力",
        category=Category.account,
        severity=Severity.medium,
        max_points=40,
        fix="确认该组织是否具备 chat 能力；API-only/Console 账号不能直接在 claude.ai 发起对话。",
        fix_type=FixType.account,
        visibility=Visibility.server,
        sources=[ACCOUNT],
    )
)
def no_chat(ctx: Context) -> RuleResult | None:
    if ctx.account is None or ctx.account.state != "active":
        return None
    if ctx.account.chat_capable is False:
        return RuleResult(Status.warn, "组织未返回 chat 能力")
    if ctx.account.chat_capable is True:
        return RuleResult(Status.ok, "组织具备 chat 能力")
    return RuleResult(Status.unknown, "组织能力字段缺失")


@rule(
    RuleMeta(
        id="account.shared",
        title="账号共享/代充（自报）",
        category=Category.account,
        severity=Severity.high,
        max_points=40,
        fix="停止账号共享与代充；账号共享违反条款，且他人的行为会牵连到你。",
        fix_type=FixType.policy,
        visibility=Visibility.local,
        sources=[POLICY],
    )
)
def shared(ctx: Context) -> RuleResult | None:
    if ctx.profile is None or ctx.profile.shared is None:
        return None
    if ctx.profile.shared:
        return RuleResult(Status.high, "自报存在账号共享/代充")
    return RuleResult(Status.ok, "自报未共享账号")


@rule(
    RuleMeta(
        id="account.multiple",
        title="多账号轮换（自报）",
        category=Category.account,
        severity=Severity.high,
        max_points=40,
        fix="停止多账号轮换；同一设备/出口的账号会互相关联。",
        fix_type=FixType.policy,
        visibility=Visibility.local,
        sources=[POLICY],
    )
)
def multiple(ctx: Context) -> RuleResult | None:
    if ctx.profile is None or ctx.profile.multiple_accounts is None:
        return None
    if ctx.profile.multiple_accounts:
        return RuleResult(Status.high, "自报存在多账号轮换")
    return RuleResult(Status.ok, "自报未使用多账号轮换")


@rule(
    RuleMeta(
        id="account.prior_ban",
        title="历史封禁（自报）",
        category=Category.account,
        severity=Severity.medium,
        max_points=30,
        fix="如实评估历史；新账号在相同设备/出口上更容易被关联。优先处理环境问题，而不是换号。",
        fix_type=FixType.policy,
        visibility=Visibility.local,
        sources=[POLICY],
    )
)
def prior_ban(ctx: Context) -> RuleResult | None:
    if ctx.profile is None or ctx.profile.prior_ban is None:
        return None
    if ctx.profile.prior_ban:
        return RuleResult(Status.warn, "自报有历史封禁")
    return RuleResult(Status.ok, "自报无历史封禁")


@rule(
    RuleMeta(
        id="account.origin",
        title="注册地与当前出口不一致",
        category=Category.account,
        severity=Severity.medium,
        max_points=25,
        fix="账号注册地与当前使用地区长期不一致会增加解释成本；不要用虚假资料注册。",
        fix_type=FixType.policy,
        visibility=Visibility.local,
        sources=[POLICY],
    )
)
def origin(ctx: Context) -> RuleResult | None:
    if ctx.profile is None or not ctx.profile.signup_country:
        return None
    code = ctx.country_code
    if not code:
        return RuleResult(Status.unknown, "出口国家未知")
    if ctx.profile.signup_country.upper() != code:
        return RuleResult(
            Status.warn,
            f"注册地 {ctx.profile.signup_country}，当前出口 {code}",
        )
    return RuleResult(Status.ok, "注册地与当前出口一致")


@rule(
    RuleMeta(
        id="account.payment",
        title="支付地与当前出口不一致",
        category=Category.account,
        severity=Severity.medium,
        max_points=25,
        fix="支付方式应与账号地区匹配；不要借用他人支付方式。",
        fix_type=FixType.policy,
        visibility=Visibility.local,
        sources=[POLICY],
    )
)
def payment(ctx: Context) -> RuleResult | None:
    if ctx.profile is None or not ctx.profile.payment_country:
        return None
    code = ctx.country_code
    if not code:
        return RuleResult(Status.unknown, "出口国家未知")
    if ctx.profile.payment_country.upper() != code:
        return RuleResult(
            Status.warn,
            f"支付地 {ctx.profile.payment_country}，当前出口 {code}",
        )
    return RuleResult(Status.ok, "支付地与当前出口一致")


@rule(
    RuleMeta(
        id="account.phone_country",
        title="手机号国家与当前出口不一致",
        category=Category.account,
        severity=Severity.medium,
        max_points=15,
        fix="手机号归属应与账号地区一致；不要借用他人手机号或接码平台。",
        fix_type=FixType.policy,
        visibility=Visibility.local,
        sources=[POLICY],
    )
)
def phone_country(ctx: Context) -> RuleResult | None:
    if ctx.profile is None or not ctx.profile.phone_country:
        return None
    code = ctx.country_code
    if not code:
        return RuleResult(Status.unknown, "出口国家未知")
    if ctx.profile.phone_country.upper() != code:
        return RuleResult(
            Status.warn,
            f"手机号国家 {ctx.profile.phone_country}，当前出口 {code}",
        )
    return RuleResult(Status.ok, "手机号国家与当前出口一致")


@rule(
    RuleMeta(
        id="account.age",
        title="账号年龄（自报）",
        category=Category.account,
        severity=Severity.low,
        max_points=10,
        fix="新账号在短时间内高频使用更容易触发审查；先稳定环境，再逐步增加使用量。",
        fix_type=FixType.policy,
        visibility=Visibility.local,
        sources=[POLICY],
    )
)
def account_age(ctx: Context) -> RuleResult | None:
    if ctx.profile is None or ctx.profile.account_age_months is None:
        return None
    age = ctx.profile.account_age_months
    if age < 1:
        return RuleResult(Status.warn, f"账号年龄约 {age} 个月")
    if age < 3:
        return RuleResult(Status.warn, f"账号年龄约 {age} 个月，仍属于较新账号")
    return RuleResult(Status.ok, f"账号年龄约 {age} 个月")


@rule(
    RuleMeta(
        id="account.unverified",
        title="账号层未验证",
        category=Category.account,
        severity=Severity.info,
        max_points=0,
        fix="如需账号层结论，运行 sentinel account（可选用 OAuth token 或 sessionKey）；不提供凭据时只能判断环境层。",
        fix_type=FixType.none,
        visibility=Visibility.local,
        sources=[ACCOUNT],
    )
)
def unverified(ctx: Context) -> RuleResult | None:
    if ctx.account is None:
        return RuleResult(Status.info, "未提供账号凭据；账号状态未知")
    return None


@rule(
    RuleMeta(
        id="account.region_blocked",
        title="账号接口返回地区限制",
        category=Category.account,
        severity=Severity.critical,
        max_points=0,
        fix="以官方区域政策为准；不要通过伪装规避地区限制。",
        fix_type=FixType.policy,
        visibility=Visibility.server,
        sources=[ACCOUNT],
    )
)
def region_blocked(ctx: Context) -> RuleResult | None:
    if ctx.account is None:
        return None
    if ctx.account.state == "region_blocked":
        return RuleResult(Status.high, ctx.account.detail or "账号接口返回地区限制")
    return None
