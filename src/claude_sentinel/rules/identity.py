"""Region, timezone, language, DNS and local-identity consistency rules."""

from __future__ import annotations

import ipaddress

from claude_sentinel.models import (
    Category,
    FixType,
    Severity,
    Status,
    Visibility,
)
from claude_sentinel.rules.context import (
    CN_TIMEZONES,
    GREATER_CHINA,
    Context,
    tz_country,
)
from claude_sentinel.rules.registry import RuleMeta, RuleResult, rule
from claude_sentinel.rules.sources import EDNS, LOCAL, REGION_GATE, SUPPORTED_REGIONS

#: Well-known Chinese ISP recursive resolvers. Used only as corroboration for
#: the local resolver list; a match is a hint, not proof on its own.
#: Ranges Clash/Surge-style clients use for fake-ip. An answer inside one of
#: these means the OS never resolved the name itself: DNS was captured.
FAKE_IP_RANGES = [
    ipaddress.ip_network("198.18.0.0/15"),  # RFC 2544, what Clash uses by default
    ipaddress.ip_network("198.19.0.0/16"),
]

CN_RESOLVER_RANGES = [
    ipaddress.ip_network("218.85.0.0/16"),  # China Telecom
    ipaddress.ip_network("202.96.0.0/12"),  # China Telecom / Unicom
    ipaddress.ip_network("114.114.114.0/24"),  # 114DNS
    ipaddress.ip_network("223.5.5.0/24"),  # AliDNS
    ipaddress.ip_network("223.6.6.0/24"),
    ipaddress.ip_network("119.29.29.0/24"),  # DNSPod
    ipaddress.ip_network("180.76.76.0/24"),  # Baidu DNS
    ipaddress.ip_network("1.2.4.0/24"),  # CNNIC
    ipaddress.ip_network("202.106.0.0/16"),  # China Unicom Beijing
]


@rule(
    RuleMeta(
        id="identity.region_runtime",
        title="官方区域闸门",
        category=Category.identity,
        severity=Severity.critical,
        max_points=0,
        fix="当前路径被官方判定为不支持地区。官方政策不允许在不受支持地区使用；不要通过改时区/语言/指纹规避。若人在支持地区，检查出口/DNS/WebRTC。",
        fix_type=FixType.policy,
        visibility=Visibility.server,
        sources=[REGION_GATE, SUPPORTED_REGIONS],
    )
)
def region_runtime(ctx: Context) -> RuleResult | None:
    if ctx.gate.region_available is False:
        return RuleResult(
            Status.high,
            f"官方返回 {ctx.gate.region_error_code or 'region_unavailable'}",
        )
    if ctx.gate.region_available is True:
        return RuleResult(Status.ok, "官方区域闸门通过")
    return RuleResult(Status.unknown, "官方区域闸门无法判断（网络/Cloudflare）")


@rule(
    RuleMeta(
        id="identity.ip_supported",
        title="出口国家 vs 官方支持列表",
        category=Category.identity,
        severity=Severity.critical,
        max_points=0,
        fix="当前出口国家不在官方支持列表。请确认实际所在地区；官方政策禁止在不受支持地区使用，不提供伪装方案。",
        fix_type=FixType.policy,
        visibility=Visibility.server,
        sources=[SUPPORTED_REGIONS],
    )
)
def ip_supported(ctx: Context) -> RuleResult | None:
    code = ctx.country_code
    if not ctx.regions or not ctx.regions.codes:
        return RuleResult(Status.unknown, "支持地区列表不可用")
    if not code:
        return RuleResult(Status.unknown, "出口国家未知")
    if code not in ctx.regions.codes:
        return RuleResult(Status.high, f"出口国家 {code} 不在官方支持列表")
    return RuleResult(Status.ok, f"出口国家 {code} 在官方支持列表")


@rule(
    RuleMeta(
        id="identity.timezone_country",
        title="系统时区 vs 出口国家",
        category=Category.identity,
        severity=Severity.high,
        max_points=40,
        fix="把系统时区调整为你实际所在地区；不要只改浏览器或只改时区来“配合”出口。",
        fix_type=FixType.locale,
        visibility=Visibility.browser_js,
        sources=[LOCAL],
    )
)
def timezone_country(ctx: Context) -> RuleResult | None:
    tz = ctx.local.timezone if ctx.local else None
    if not tz:
        return RuleResult(Status.unknown, "系统时区未知")
    mapped = tz_country(tz)
    if not mapped:
        return None
    code = ctx.country_code
    if not code:
        return RuleResult(Status.unknown, "出口国家未知")
    if mapped != code:
        return RuleResult(
            Status.high,
            f"系统时区 {tz}（{mapped}）与出口国家 {code} 不一致",
            details={"timezone": tz, "timezone_country": mapped, "ip_country": code},
        )
    return RuleResult(Status.ok, f"时区 {tz} 与出口国家 {code} 一致")


@rule(
    RuleMeta(
        id="identity.lang_country",
        title="系统语言 vs 出口国家",
        category=Category.identity,
        severity=Severity.medium,
        max_points=25,
        fix="使用与你实际所在地区一致的系统语言；不要为了“看起来像”而单独改浏览器语言。",
        fix_type=FixType.locale,
        visibility=Visibility.browser_js,
        sources=[LOCAL],
    )
)
def lang_country(ctx: Context) -> RuleResult | None:
    if not ctx.local:
        return None
    primary = ctx.local.locale or (ctx.local.languages[0] if ctx.local.languages else "")
    is_zh = bool(primary and primary.lower().startswith("zh"))
    if not is_zh:
        return RuleResult(Status.ok, "系统语言不是中文，未发现该冲突")
    code = ctx.country_code
    if not code:
        return RuleResult(Status.unknown, "出口国家未知")
    if code not in GREATER_CHINA and code != "SG":
        return RuleResult(
            Status.warn,
            f"系统语言为中文，但出口国家是 {code}",
            details={"locale": ctx.local.locale, "languages": ctx.local.languages},
        )
    return RuleResult(Status.ok, f"中文环境与出口国家 {code} 不矛盾")


@rule(
    RuleMeta(
        id="identity.cn_fonts",
        title="中文字体（弱信号）",
        category=Category.identity,
        severity=Severity.low,
        max_points=10,
        fix="字体只是弱信号，不单独说明问题。若你实际在支持地区，使用国际主流浏览器即可。",
        fix_type=FixType.none,
        visibility=Visibility.local,
        sources=[LOCAL],
    )
)
def cn_fonts(ctx: Context) -> RuleResult | None:
    if not ctx.local or not ctx.local.fonts_cn:
        return RuleResult(Status.ok, "未发现常见中文字体")
    code = ctx.country_code
    if code and code not in GREATER_CHINA:
        return RuleResult(
            Status.warn,
            "发现中文字体：" + ", ".join(ctx.local.fonts_cn[:4]),
        )
    return RuleResult(Status.ok, "中文字体与当前地区不矛盾")


@rule(
    RuleMeta(
        id="identity.cn_browser",
        title="国产浏览器（弱信号）",
        category=Category.identity,
        severity=Severity.low,
        max_points=10,
        fix="如你实际在支持地区，改用国际主流浏览器；不要使用带代理/指纹修改插件的“防关联”浏览器。",
        fix_type=FixType.none,
        visibility=Visibility.local,
        sources=[LOCAL],
    )
)
def cn_browser(ctx: Context) -> RuleResult | None:
    from claude_sentinel.rules.context import CN_BROWSER_HINTS

    if not ctx.local or not ctx.local.browsers:
        return RuleResult(Status.ok, "未发现国产浏览器")
    hits = [b for b in ctx.local.browsers if any(h in b for h in CN_BROWSER_HINTS)]
    if not hits:
        return RuleResult(Status.ok, "未发现国产浏览器")
    code = ctx.country_code
    if code and code not in GREATER_CHINA:
        return RuleResult(Status.warn, "发现国产浏览器：" + ", ".join(hits))
    return RuleResult(Status.ok, "国产浏览器与当前地区不矛盾")


@rule(
    RuleMeta(
        id="identity.dns_country",
        title="DNS 解析器 vs 出口国家",
        category=Category.identity,
        severity=Severity.medium,
        max_points=20,
        fix="让 DNS 与 HTTP 走同一路径，避免分流不完整；不要只改 HTTP 代理而让 DNS 直连。",
        fix_type=FixType.network,
        visibility=Visibility.server,
        sources=[EDNS],
    )
)
def dns_country(ctx: Context) -> RuleResult | None:
    obs = ctx.obs("net.dns")
    if not obs or not isinstance(obs.value, dict):
        return RuleResult(Status.unknown, "DNS 解析器信息不可用")
    geo = str(obs.value.get("geo") or "").lower()
    if not geo:
        return RuleResult(Status.unknown, "DNS 解析器地理位置未知")
    code = ctx.country_code
    if not code:
        return RuleResult(Status.unknown, "出口国家未知")
    if "china" in geo and code != "CN":
        return RuleResult(
            Status.warn,
            f"DNS 解析器在中国，但出口国家是 {code}",
            details={"dns_geo": obs.value.get("geo"), "ip_country": code},
        )
    return RuleResult(Status.ok, "DNS 解析器与出口国家未发现明显冲突")


@rule(
    RuleMeta(
        id="identity.clock",
        title="系统时钟偏差",
        category=Category.identity,
        severity=Severity.medium,
        max_points=15,
        fix="开启系统自动校时；OAuth、Cloudflare 和 JWT 对时间敏感。",
        fix_type=FixType.locale,
        visibility=Visibility.local,
        sources=[REGION_GATE],
    )
)
def clock(ctx: Context) -> RuleResult | None:
    offset = ctx.gate.clock_offset
    if offset is None:
        return RuleResult(Status.unknown, "无法获取服务器时间")
    if abs(offset) > 300:
        return RuleResult(Status.high, f"偏差 {offset:+.0f}s，超过 5 分钟")
    if abs(offset) > 120:
        return RuleResult(Status.warn, f"偏差 {offset:+.0f}s，建议校时")
    return RuleResult(Status.ok, f"偏差 {offset:+.1f}s")


@rule(
    RuleMeta(
        id="identity.cn_timezone_note",
        title="中国时区标记（信息）",
        category=Category.identity,
        severity=Severity.info,
        max_points=0,
        fix="这是信息项，不是单独的风险证据；请结合官方区域闸门和出口一起看。",
        fix_type=FixType.none,
        visibility=Visibility.browser_js,
        sources=[LOCAL],
    )
)
def cn_timezone_note(ctx: Context) -> RuleResult | None:
    tz = ctx.local.timezone if ctx.local else None
    if tz in CN_TIMEZONES:
        return RuleResult(Status.info, f"系统时区为 {tz}")
    return None


@rule(
    RuleMeta(
        id="identity.dns_leak",
        title="DNS 泄露：本地解析器走了国内",
        category=Category.identity,
        severity=Severity.high,
        max_points=30,
        fix=(
            "让 DNS 与 HTTP 走同一路径：开启 TUN/增强模式，或把 DNS 交给代理远端解析"
            "（fake-ip / remote DNS）。只给 HTTP 配代理、DNS 仍用本地 ISP，"
            "目标站点与 CDN 仍能看出你实际在国内。"
        ),
        fix_type=FixType.network,
        visibility=Visibility.server,
        sources=[LOCAL, EDNS],
    )
)
def dns_leak(ctx: Context) -> RuleResult | None:
    """Is DNS actually leaking, or merely configured with a domestic server?

    A configured CN resolver is NOT proof of a leak: a TUN with fake-ip
    captures the queries, answers with 198.18.x.x placeholders and resolves
    upstream through the proxy. What matters is whether the answer the OS gets
    is a fake-ip (captured) or a real address (leaked).
    """
    mode = ctx.network_mode
    resolvers = mode.local_resolvers if mode else []
    country = ctx.country_code
    if not resolvers:
        return RuleResult(Status.unknown, "未能读取系统 DNS 解析器")
    if not country:
        return RuleResult(Status.unknown, "出口国家未知，无法对比 DNS")

    captured = dns_captured(ctx)
    if captured is True:
        note = "（解析器看似国内，但被 fake-ip 接管，实际由代理解析）" if _has_cn_resolver(ctx, resolvers) else ""
        return RuleResult(Status.ok, f"DNS 查询已被 TUN 接管{note}")
    if captured is None and mode is not None and mode.tun_active and _has_cn_resolver(ctx, resolvers):
        # TUN is up but we cannot prove capture: say so instead of crying leak.
        return RuleResult(
            Status.warn,
            "TUN 已开启，但无法确认 DNS 是否被接管；建议核对 fake-ip 配置",
        )

    domestic_cn = [ip for ip in resolvers if _looks_cn_resolver(ctx, ip)]
    if country != "CN" and domestic_cn:
        return RuleResult(
            Status.high,
            f"出口在 {country}，但系统 DNS 使用 {len(domestic_cn)} 个国内解析器："
            + ", ".join(domestic_cn[:3]),
            details={"resolvers": resolvers, "country": country},
        )
    if country != "CN" and ctx.obs("net.dns"):
        obs = ctx.obs("net.dns")
        geo = str((obs.value or {}).get("geo") or "").lower()
        if "china" in geo:
            return RuleResult(
                Status.high,
                f"出口在 {country}，但实际生效的 DNS 出口解析器在中国（{geo}）",
                details={"resolvers": resolvers, "dns_geo": geo},
            )
    return RuleResult(Status.ok, f"DNS 未见与出口国家（{country}）冲突")


def _looks_cn_resolver(ctx: Context, ip: str) -> bool:
    """Whether a resolver is a domestic (CN) one.

    Two independent signals: the ECS probe localised the *same* resolver to
    China, or the address sits in a well-known Chinese ISP range. The second
    must still run when the probe is unavailable -- otherwise the most common
    configuration (local ISP resolver, no probe data) would read as "clean".
    """
    obs = ctx.obs("net.dns")
    if obs and isinstance(obs.value, dict):
        geo = str(obs.value.get("geo") or "").lower()
        probed = str(obs.value.get("ip") or "")
        if probed and probed == ip and "china" in geo:
            return True
    return _resolver_in_cn_ranges(ip)


def _resolver_in_cn_ranges(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for network in CN_RESOLVER_RANGES:
        if addr in network:
            return True
    return False

def _has_cn_resolver(ctx: Context, resolvers: list[str]) -> bool:
    return any(_looks_cn_resolver(ctx, ip) for ip in resolvers)


def dns_captured(ctx: Context) -> bool | None:
    """Did the OS resolve a hostname to a fake-ip placeholder?

    ``True``  -> TUN/fake-ip captured DNS (no leak, regardless of nameserver)
    ``False`` -> a real public address came back (DNS went out for real)
    ``None``  -> no usable sample
    """
    obs = ctx.obs("net.dns_resolution")
    if not obs or not isinstance(obs.value, dict):
        return None
    answers = obs.value.get("answers") or []
    if not answers:
        return None
    for answer in answers:
        try:
            addr = ipaddress.ip_address(str(answer))
        except ValueError:
            continue
        # NOTE: `addr in [network, ...]` compares equality, it does NOT test
        # containment -- that silently returns False for every address.
        if any(addr in network for network in FAKE_IP_RANGES):
            return True
    return False
