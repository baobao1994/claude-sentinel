"""Verdict: hard gates first, then risk bands, with explicit uncertainty."""

from __future__ import annotations

from claude_sentinel.models import (
    Confidence,
    Finding,
    Severity,
    Status,
    Verdict,
    VerdictCode,
)
from claude_sentinel.rules.context import Context

SEVERITY_RANK = {
    Severity.critical: 0,
    Severity.high: 1,
    Severity.medium: 2,
    Severity.low: 3,
    Severity.info: 4,
}


def _top_fixes(findings: list[Finding], limit: int = 3) -> list[str]:
    candidates = [
        f
        for f in findings
        if f.fix and f.status in {Status.high, Status.warn} and f.max_points > 0
    ]
    candidates.sort(key=lambda f: (SEVERITY_RANK.get(f.severity, 9), -f.points))
    result: list[str] = []
    for finding in candidates:
        fix = finding.fix.strip()
        if fix and fix not in result:
            result.append(fix)
        if len(result) >= limit:
            break
    return result


def _account_note(ctx: Context) -> str:
    if ctx.account is None:
        return "账号层：参考模式（未提供凭据）；本报告只评估环境，不代表账号真实状态。"
    state = ctx.account.state
    if state == "active":
        if ctx.account.chat_capable is False:
            return "账号层：会话有效，但该组织可能没有 Claude.ai 对话能力。"
        return "账号层：已验证可用。"
    if state == "expired":
        return "账号层：会话已失效，需要重新登录（不是封号）。"
    if state == "disabled":
        return "账号层：官方状态为已停用。"
    if state == "region_blocked":
        return "账号层：账号接口返回地区限制。"
    if state == "challenge":
        return "账号层：遇到 Cloudflare 挑战，无法判断。"
    return "账号层：无法判断。"


def build_verdict(
    ctx: Context,
    findings: list[Finding],
    score: float | None,
    level: str,
    coverage: float,
    confidence: Confidence,
) -> Verdict:
    account_note = _account_note(ctx)

    # 1. Account disabled is the strongest official signal.
    if ctx.account is not None and ctx.account.state == "disabled":
        return Verdict(
            code=VerdictCode.blocked_account,
            title="官方账号限制",
            headline="不可发起对话",
            reason="官方账号接口显示该账号已被停用。",
            can_start=False,
            account_note=account_note,
            confidence=Confidence.high,
            gate="account",
            top_fixes=[
                "通过官方申诉入口提交，保留账号信息与触发时间。",
                "不要用新账号/新设备规避，可能扩大关联封禁。",
                "在申诉结果出来前，停止在同一环境继续批量操作。",
            ],
        )

    # 2. Region gate / supported-country list.
    gate_blocked = ctx.gate.region_available is False
    list_blocked = bool(
        ctx.regions and ctx.country_code and ctx.country_code not in ctx.regions.codes
    )
    account_region = ctx.account is not None and ctx.account.state == "region_blocked"
    if gate_blocked or list_blocked or account_region:
        code = ctx.gate.region_error_code or "region_unavailable"
        if gate_blocked:
            reason = f"官方返回 {code}；当前网络路径所在地区不在支持范围。"
        elif account_region:
            reason = "账号接口返回地区限制；请以官方支持地区政策为准。"
        elif ctx.gate.region_available is True:
            reason = (
                f"官方区域闸门通过，但出口国家 {ctx.country_code} 不在官方支持列表；"
                "两条路径不一致，需检查代理/DNS/IPv6 分流。"
            )
        else:
            reason = (
                f"出口国家 {ctx.country_code} 不在官方支持列表；"
                "官方区域闸门当前无法判断（网络/Cloudflare）。"
            )
        return Verdict(
            code=VerdictCode.blocked_region,
            title="官方区域限制",
            headline="不可发起对话",
            reason=reason,
            can_start=False,
            account_note=account_note,
            confidence=Confidence.high,
            gate="region",
            top_fixes=[
                "确认你实际所在地区与官方支持列表；不受支持地区不应使用该服务。",
                "若你人在支持地区，检查出口 IP、DNS、WebRTC、IPv6 是否走了不支持地区。",
                "不要通过修改时区/语言/浏览器指纹规避地区限制。",
            ],
        )

    # 3. Official service outage.
    if ctx.status is not None and not ctx.status.relevant_ok:
        return Verdict(
            code=VerdictCode.blocked_service,
            title="官方服务异常",
            headline="暂不可发起对话",
            reason="官方状态页显示相关组件未处于 operational。",
            can_start=False,
            account_note=account_note,
            confidence=Confidence.high,
            gate="service",
            top_fixes=[
                "查看 status.claude.com 的组件状态与事件更新。",
                "等待恢复后重试；不要反复重试制造更多失败请求。",
            ],
        )

    # 4. Clock skew makes OAuth/Cloudflare unreliable.
    if ctx.gate.clock_offset is not None and abs(ctx.gate.clock_offset) > 300:
        return Verdict(
            code=VerdictCode.blocked_clock,
            title="系统时钟偏差",
            headline="先校准系统时间",
            reason=f"本机与服务器相差 {ctx.gate.clock_offset:+.0f} 秒，超过 5 分钟。",
            can_start=False,
            account_note=account_note,
            confidence=Confidence.high,
            gate="clock",
            top_fixes=["开启系统自动校时，确认偏差小于 5 分钟后重测。"],
        )

    # 5. Not enough data. A positive verdict needs a country and enough coverage.
    if score is None or coverage < 0.6 or ctx.country_code is None:
        missing = _missing_evidence(ctx, coverage, score)
        return Verdict(
            code=VerdictCode.unknown,
            title="数据不足",
            headline="无法判断",
            reason=f"关键数据不足：{missing[0]}。因此不能给出“可以发起”的结论。",
            can_start=None,
            account_note=account_note,
            confidence=Confidence.low,
            gate="data",
            top_fixes=missing[1:],
        )

    # 6. Safety bands (100 = cleanest). Higher is better.
    if score >= 86:
        code, title, headline = VerdictCode.ready, "环境层通过", "可以发起对话"
        can_start = True
        reason = "官方区域闸门与服务状态正常，安全分处于高位。"
    elif score >= 66:
        code, title, headline = VerdictCode.caution, "有可改进项", "可以，但建议先处理"
        can_start = True
        reason = "环境基本可用，但存在若干可改进项。"
    elif score >= 41:
        code, title, headline = VerdictCode.high_caution, "风险偏高", "谨慎发起"
        can_start = True
        reason = "存在多项高风险信号；建议先修复再发起对话。"
    else:
        code, title, headline = VerdictCode.do_not_start, "风险很高", "不建议发起"
        can_start = False
        reason = "存在决定性问题（安全分被单条严重发现压制）；建议先停手整改。"

    fixes = _top_fixes(findings)
    if not fixes:
        fixes = ["保持当前环境稳定，避免短时间切换出口/时区/浏览器。", "定期复测并查看历史漂移。"]

    return Verdict(
        code=code,
        title=title,
        headline=headline,
        reason=reason,
        can_start=can_start,
        account_note=account_note,
        confidence=confidence,
        gate=None,
        top_fixes=fixes,
    )

def _missing_evidence(ctx: Context, coverage: float, score: float | None) -> list[str]:
    """Name the exact gaps and pair each with a concrete action.

    A bare "insufficient data" is unactionable: the user cannot tell whether to
    fix their proxy, wait out a blip, or ignore it. The first element is the
    summary sentence; the rest are "缺什么 → 怎么补" lines.
    """
    gaps: list[tuple[str, str]] = []

    if ctx.country_code is None:
        gaps.append((
            "出口国家未知",
            "确认代理覆盖 claude.ai 与 anthropic.com；打开 "
            "https://claude.ai/cdn-cgi/trace 能返回 ip= 即代表出口可测",
        ))

    trace_keys = ("trace.claude", "trace.anthropic", "trace.api", "trace.cf")
    reachable = [key for key in trace_keys if any(t.key == key and t.ok for t in ctx.traces)]
    if ctx.country_code is not None and len(reachable) < 2:
        gaps.append((
            "仅 1 条出口路径可测",
            "放行 api.anthropic.com 与 www.cloudflare.com 的 /cdn-cgi/trace，"
            "以便对比浏览器与 Claude Code 是否走同一出口",
        ))

    if ctx.gate.region_available is None:
        gaps.append((
            "官方区域闸门不可达",
            "在浏览器打开 claude.ai 确认能正常加载；若它被拦截，"
            "闸门与状态页都会失败",
        ))

    if ctx.status is None or ctx.status.indicator == "unknown":
        gaps.append((
            "官方服务状态不可达",
            "确认 status.claude.com 可访问；它只用于排除服务端故障",
        ))

    if score is None and ctx.country_code is not None:
        gaps.append((
            "六轴评分项不足",
            "补齐网络与客户端数据后重跑；单项缺失不会掩盖其余结论",
        ))

    if coverage < 0.6 and not gaps:
        gaps.append((
            f"覆盖率仅 {coverage * 100:.0f}%",
            "重跑一次通常即可恢复；若持续偏低，检查代理是否对部分域名间歇性失效",
        ))

    if not gaps:
        gaps.append(("关键数据源不可达", "稍后重试；不要因为没报错就认为安全"))

    summary = "、".join(gap for gap, _ in gaps[:3])
    lines = [f"缺 {gap} → {action}" for gap, action in gaps]
    return [summary, *lines[:5]]
