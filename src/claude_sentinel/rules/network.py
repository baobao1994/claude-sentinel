"""Network egress and IP reputation rules."""

from __future__ import annotations

from datetime import datetime

from claude_sentinel.models import (
    Category,
    FixType,
    Severity,
    Status,
    Visibility,
)
from claude_sentinel.rules.context import Context
from claude_sentinel.rules.registry import RuleMeta, RuleResult, rule
from claude_sentinel.rules.sources import ABUSEIPDB, IP_API, PROXYCHECK, RDAP, RIPESTAT


@rule(
    RuleMeta(
        id="ip.rpki_invalid",
        title="出口前缀的 RPKI 校验未通过",
        category=Category.ip,
        severity=Severity.medium,
        max_points=15,
        fix=(
            "该前缀的 BGP 起源与 RPKI 授权不一致（或无授权），更容易被劫持或误路由。"
            "优先换到 RPKI 有效的网络；这是路由层面的客观问题，不是你的配置能修的。"
        ),
        fix_type=FixType.network,
        visibility=Visibility.server,
        sources=[RIPESTAT],
    )
)
def rpki_invalid(ctx: Context) -> RuleResult | None:
    info = ctx.rpki
    if info is None or not info.ok or not info.status:
        return RuleResult(Status.unknown, "RPKI 校验数据不可用")
    status = info.status.lower()
    if status == "valid":
        return RuleResult(Status.ok, f"{info.prefix or '前缀'} · RPKI 有效")
    label = {
        "invalid_length": "前缀长度不合法",
        "invalid_asn": "起源 ASN 不合法",
        "invalid": "无效",
    }.get(status, status)
    return RuleResult(
        Status.warn,
        f"{info.prefix or '前缀'} · RPKI {label}",
        details={"status": status, "prefix": info.prefix},
    )


@rule(
    RuleMeta(
        id="ip.asn_kind",
        title="出口属于机房/云厂商 ASN",
        category=Category.ip,
        severity=Severity.medium,
        max_points=15,
        fix=(
            "骨干网或运营商 ASN 更接近真实用户；云厂商 ASN 的出口通常被大量脚本共用。"
            "如非必要，改用本地宽带出口。"
        ),
        fix_type=FixType.network,
        visibility=Visibility.server,
        sources=[IP_API],
    )
)
def asn_kind(ctx: Context) -> RuleResult | None:
    if ctx.ip is None or not ctx.ip.asn_kind:
        return RuleResult(Status.unknown, "数据源未返回 ASN 类型")
    kind = ctx.ip.asn_kind.lower()
    if kind in {"hosting", "datacenter", "cloud", "business"}:
        return RuleResult(Status.warn, f"ASN 类型为 {kind}（{ctx.ip.asn or '—'}）")
    if kind in {"isp", "backbone", "education", "government"}:
        return RuleResult(Status.ok, f"ASN 类型为 {kind}（{ctx.ip.asn or '—'}）")
    return RuleResult(Status.unknown, f"ASN 类型 {kind} 未归类")


@rule(
    RuleMeta(
        id="ip.tor",
        title="出口被识别为 Tor",
        category=Category.ip,
        severity=Severity.critical,
        max_points=20,
        fix="Tor 出口通常与高风险匿名流量关联。停止使用 Tor 访问 Claude；使用你实际所在地区的正常网络。",
        fix_type=FixType.network,
        visibility=Visibility.server,
        sources=[PROXYCHECK],
        description="只有 proxycheck.io 等覆盖 Tor 检测的数据源才能确认。",
    )
)
def tor(ctx: Context) -> RuleResult | None:
    if ctx.ip is None:
        return RuleResult(Status.unknown, "没有出口 IP 数据")
    if ctx.ip.is_tor is True:
        return RuleResult(Status.high, "出口被识别为 Tor")
    if ctx.ip.is_tor is False:
        return RuleResult(Status.ok, "未发现 Tor 标记")
    return RuleResult(Status.unknown, "现有数据源未覆盖 Tor 检测")


@rule(
    RuleMeta(
        id="ip.abuse",
        title="出口有滥用/高风险记录",
        category=Category.ip,
        severity=Severity.high,
        max_points=30,
        fix="更换出口网络，避免使用被大量举报的公共节点；不要在同一出口上运行批量脚本。",
        fix_type=FixType.network,
        visibility=Visibility.server,
        sources=[IP_API, ABUSEIPDB],
    )
)
def abuse(ctx: Context) -> RuleResult | None:
    if ctx.ip is None:
        return RuleResult(Status.unknown, "没有出口 IP 数据")
    if ctx.ip.is_abuser is True:
        return RuleResult(Status.high, "数据源标记该 IP 为滥用来源")
    if ctx.ip.risk is not None:
        if ctx.ip.risk >= 70:
            return RuleResult(Status.high, f"风险分 {ctx.ip.risk:.0f}/100")
        if ctx.ip.risk >= 25:
            return RuleResult(Status.warn, f"风险分 {ctx.ip.risk:.0f}/100")
        return RuleResult(Status.ok, f"风险分 {ctx.ip.risk:.0f}/100")
    if ctx.ip.is_abuser is False:
        return RuleResult(Status.ok, "未发现滥用标记")
    return RuleResult(Status.unknown, "数据源未返回滥用/风险分")


@rule(
    RuleMeta(
        id="ip.proxy_vpn",
        title="出口是代理/VPN",
        category=Category.ip,
        severity=Severity.high,
        max_points=30,
        fix="共享代理/VPN 出口容易被多人行为牵连。改用稳定、非共享的网络；不要在短时间内切换多个节点。",
        fix_type=FixType.network,
        visibility=Visibility.server,
        sources=[IP_API, PROXYCHECK],
    )
)
def proxy_vpn(ctx: Context) -> RuleResult | None:
    if ctx.ip is None:
        return RuleResult(Status.unknown, "没有出口 IP 数据")
    if ctx.ip.is_proxy is True or ctx.ip.is_vpn is True:
        flags = []
        if ctx.ip.is_proxy:
            flags.append("代理")
        if ctx.ip.is_vpn:
            flags.append("VPN")
        return RuleResult(Status.high, "出口被识别为 " + "/".join(flags))
    if ctx.ip.is_proxy is False or ctx.ip.is_vpn is False:
        return RuleResult(Status.ok, "未发现代理/VPN 标记")
    return RuleResult(Status.unknown, "数据源未返回代理/VPN 标记")


@rule(
    RuleMeta(
        id="ip.datacenter",
        title="出口是机房/托管 IP",
        category=Category.ip,
        severity=Severity.high,
        max_points=30,
        fix="机房 IP 常被云服务/脚本共用。改用住宅或企业宽带出口；如果必须用云主机，至少固定一个干净出口。",
        fix_type=FixType.network,
        visibility=Visibility.server,
        sources=[IP_API, PROXYCHECK],
    )
)
def datacenter(ctx: Context) -> RuleResult | None:
    if ctx.ip is None:
        return RuleResult(Status.unknown, "没有出口 IP 数据")
    if ctx.ip.is_datacenter is True:
        return RuleResult(Status.high, "出口被识别为数据中心/托管网络")
    if ctx.ip.is_datacenter is False:
        return RuleResult(Status.ok, "不是数据中心 IP")
    return RuleResult(Status.unknown, "数据源未返回 hosting 标记")


@rule(
    RuleMeta(
        id="ip.mobile_cgnat",
        title="移动网络/CGNAT 共享出口",
        category=Category.ip,
        severity=Severity.medium,
        max_points=10,
        fix="移动网络大流量共享出口会放大他人行为。若频繁异常，改用固定宽带。",
        fix_type=FixType.network,
        visibility=Visibility.server,
        sources=[IP_API],
    )
)
def mobile(ctx: Context) -> RuleResult | None:
    if ctx.ip is None:
        return None
    if ctx.ip.is_mobile is True:
        return RuleResult(Status.warn, "出口是移动网络/CGNAT，可能多人共享")
    if ctx.ip.is_mobile is False:
        return RuleResult(Status.ok, "不是移动网络出口")
    return RuleResult(Status.unknown, "数据源未返回 mobile 标记")


@rule(
    RuleMeta(
        id="ip.recent_allocation",
        title="IP 段是近期新分配的",
        category=Category.ip,
        severity=Severity.low,
        max_points=10,
        fix="新分配 IP 段可能缺少信誉历史。优先使用稳定、使用时间较长的出口。",
        fix_type=FixType.network,
        visibility=Visibility.server,
        sources=[RDAP],
    )
)
def recent_allocation(ctx: Context) -> RuleResult | None:
    if not ctx.rdap or not ctx.rdap.ok or not ctx.rdap.registration:
        return RuleResult(Status.unknown, "RDAP 注册时间不可用")
    try:
        registered = datetime.fromisoformat(ctx.rdap.registration.replace("Z", "+00:00"))
    except ValueError:
        return RuleResult(Status.unknown, "RDAP 注册时间无法解析")
    age_days = (ctx.now - registered).days
    if age_days < 180:
        return RuleResult(Status.warn, f"IP 段注册仅 {age_days} 天")
    return RuleResult(Status.ok, f"IP 段注册 {age_days} 天")


@rule(
    RuleMeta(
        id="ip.provider_disagreement",
        title="IP 情报数据源结论不一致",
        category=Category.ip,
        severity=Severity.low,
        max_points=5,
        fix="不要把单一数据源的结论当事实；以官方响应和多家一致的结果为准。",
        fix_type=FixType.none,
        visibility=Visibility.local,
        sources=[IP_API, PROXYCHECK],
    )
)
def disagreement(ctx: Context) -> RuleResult | None:
    if ctx.ip is None or ctx.ip.providers_ok < 2:
        return RuleResult(Status.unknown, "可用数据源不足 2 个")
    if ctx.ip.disagreements:
        return RuleResult(
            Status.warn,
            "数据源在以下字段不一致：" + ", ".join(ctx.ip.disagreements),
        )
    return RuleResult(Status.ok, "多源结论一致")


@rule(
    RuleMeta(
        id="ip.no_data",
        title="出口 IP 情报不可用",
        category=Category.ip,
        severity=Severity.medium,
        max_points=10,
        fix="检查网络或稍后重试；在数据缺失时不要得出“安全”的结论。",
        fix_type=FixType.none,
        visibility=Visibility.local,
        sources=[IP_API],
    )
)
def no_data(ctx: Context) -> RuleResult | None:
    if ctx.ip is None:
        return RuleResult(Status.unknown, "没有获取到出口 IP")
    if ctx.ip.providers_ok == 0:
        return RuleResult(Status.unknown, "所有 IP 情报数据源均不可达")
    return RuleResult(Status.ok, f"{ctx.ip.providers_ok}/{ctx.ip.providers_total} 个数据源可用")
