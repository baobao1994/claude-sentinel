"""Official Anthropic signals: region gate, supported regions, status, clock."""

from __future__ import annotations

import json
import re
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from bs4 import BeautifulSoup

from claude_sentinel.collectors.base import (
    Http,
    cache_read,
    cache_write,
    parse_json,
    source_from_response,
)
from claude_sentinel.config import Settings, package_data_text
from claude_sentinel.models import (
    Confidence,
    Observation,
    RegionList,
    ServiceStatus,
    Source,
    SourceKind,
    Status,
    StatusComponent,
)

REGION_GATE_URL = "https://claude.ai/api/organizations"
LOGIN_URL = "https://claude.ai/login"
SUPPORTED_URL = "https://www.anthropic.com/supported-countries"
STATUS_URL = "https://status.claude.com/api/v2/summary.json"
CLAUDE_URL = "https://claude.ai/"
API_URL = "https://api.anthropic.com/"

REGION_CACHE_TTL = 7 * 24 * 3600
STATUS_CACHE_TTL = 60


def _norm(name: str) -> str:
    return (
        name.replace("’", "'")
        .replace("‘", "'")
        .strip()
        .lower()
    )


def _aliases() -> dict[str, str]:
    data = json.loads(package_data_text("region_aliases.json"))
    return data.get("by_name", {})


def _bundled_regions() -> RegionList:
    data = json.loads(package_data_text("regions.json"))
    countries = data.get("countries", [])
    return RegionList(
        codes={c["code"] for c in countries},
        names={c["code"]: c["name"] for c in countries},
        effective=data.get("effective"),
        fetched_at=datetime.fromisoformat(data["fetched_at"])
        if data.get("fetched_at")
        else datetime.now(timezone.utc),
        source_url=data.get("source_url", SUPPORTED_URL),
        scope=data.get("scope", "all"),
        stale=True,
    )


def parse_supported_page(text: str, source_url: str = SUPPORTED_URL) -> RegionList:
    """Parse the country list from Anthropic's public policy page.

    The page also contains navigation lists and a three-item "Use by ..." list,
    so we intentionally select the largest <ul> and sanity-check its size.
    """
    soup = BeautifulSoup(text, "html.parser")
    uls = soup.find_all("ul")
    if not uls:
        raise ValueError("no <ul> found on supported-countries page")
    # The page may contain one unified list or separate API / Claude.ai lists.
    # Union every list with at least 50 items instead of picking just one.
    lists = [u for u in uls if len(u.find_all("li")) >= 50]
    if not lists:
        raise ValueError("country lists too small")

    aliases = _aliases()
    codes: set[str] = set()
    names: dict[str, str] = {}
    unknown: list[str] = []
    for ul in lists:
        for li in ul.find_all("li"):
            name = li.get_text(" ", strip=True)
            if not name or len(name) > 80 or name.lower().startswith("use by"):
                continue
            code = aliases.get(name) or aliases.get(_norm(name))
            if not code:
                if name not in unknown:
                    unknown.append(name)
                continue
            codes.add(code)
            names[code] = name

    if len(codes) < 50:
        raise ValueError(f"mapped too few countries: {len(codes)}")

    effective = None
    m = re.search(
        r"Effective\s+([A-Z][a-z]+ \d{1,2}, \d{4})", soup.get_text(" ", strip=True)
    )
    if m:
        effective = m.group(1)

    return RegionList(
        codes=codes,
        names=names,
        effective=effective,
        source_url=source_url,
        scope="all",
        unknown_names=unknown,
    )


def load_regions(
    http: Http,
    settings: Settings,
    force_refresh: bool = False,
) -> tuple[RegionList, Observation]:
    cached = None if force_refresh else cache_read(settings.cache_dir, "supported_regions", REGION_CACHE_TTL)
    if cached:
        try:
            data = json.loads(cached) if isinstance(cached, str) else cached
            regions = RegionList.model_validate(data)
            regions.from_cache = True
            obs = Observation(
                key="region.list",
                label="官方支持地区列表",
                value={"count": len(regions.codes), "effective": regions.effective},
                status=Status.ok,
                source=Source(
                    name="Anthropic Supported Regions Policy",
                    kind=SourceKind.official,
                    url=SUPPORTED_URL,
                    retrieved_at=regions.fetched_at,
                    confidence=Confidence.high,
                ),
                visibility="server",
                detail=f"{len(regions.codes)} 个国家/地区（缓存）",
            )
            return regions, obs
        except Exception:
            pass

    resp = None
    try:
        resp = http.fetch(SUPPORTED_URL, follow_redirects=True)
        resp.raise_for_status()
        regions = parse_supported_page(resp.text, SUPPORTED_URL)
        regions.from_cache = False
        cache_write(settings.cache_dir, "supported_regions", regions.model_dump(mode="json"))
        obs = Observation(
            key="region.list",
            label="官方支持地区列表",
            value={"count": len(regions.codes), "effective": regions.effective},
            status=Status.ok,
            source=source_from_response(
                "Anthropic Supported Regions Policy", SourceKind.official, SUPPORTED_URL, resp
            ),
            visibility="server",
            detail=f"{len(regions.codes)} 个国家/地区",
        )
        return regions, obs
    except Exception as exc:  # noqa: BLE001 - degrade, never crash
        fallback = _bundled_regions()
        obs = Observation(
            key="region.list",
            label="官方支持地区列表",
            value={"count": len(fallback.codes), "effective": fallback.effective},
            status=Status.warn,
            source=Source(
                name="Anthropic Supported Regions Policy (bundled snapshot)",
                kind=SourceKind.official,
                url=SUPPORTED_URL,
                confidence=Confidence.medium,
                note="在线抓取失败，使用内置快照",
            ),
            visibility="server",
            detail=f"使用内置快照：{len(fallback.codes)} 个国家/地区",
            error=str(exc),
        )
        return fallback, obs


def _error_payload(resp) -> tuple[str | None, str | None]:
    data = parse_json(resp)
    if not isinstance(data, dict):
        return None, None
    err = data.get("error") or {}
    details = err.get("details") or {}
    code = details.get("error_code")
    message = err.get("message") or details.get("message")
    return code, message


def check_region_gate(http: Http) -> Observation:
    source = Source(
        name="Claude region gate",
        kind=SourceKind.official,
        url=REGION_GATE_URL,
        confidence=Confidence.high,
    )
    started = time.monotonic()
    try:
        resp = http.fetch(
            REGION_GATE_URL,
            headers={"Accept": "application/json", "Cache-Control": "no-cache"},
        )
    except Exception as exc:  # noqa: BLE001
        obs = Observation(
            key="official.region_gate",
            label="官方区域闸门",
            value={"available": None},
            status=Status.unknown,
            source=source,
            visibility="server",
            detail="无法连接 claude.ai 区域接口",
            error=str(exc),
            latency_ms=int((time.monotonic() - started) * 1000),
        )
        return _region_fallback(http, obs)

    latency = int((time.monotonic() - started) * 1000)
    code, message = _error_payload(resp)
    available: bool | None = None
    detail = ""

    if resp.status_code == 200:
        available = True
        detail = "接口返回 200，当前路径地区可用"
    elif code == "region_unavailable":
        available = False
        detail = "官方返回 region_unavailable：当前路径所在地区不受支持"
    elif code in {"account_session_invalid", "authentication_error"}:
        available = True
        detail = f"官方返回 {code}：地区可用，只是未登录/会话无效"
    elif resp.status_code == 401:
        available = True
        detail = "HTTP 401：地区可用，需要登录"
    elif resp.status_code == 429:
        detail = "HTTP 429：被限流，无法判断"
    elif resp.status_code in {403, 503} and (
        resp.headers.get("cf-mitigated") or "text/html" in resp.headers.get("content-type", "")
    ):
        challenge = resp.headers.get("cf-mitigated") or ""
        detail = (
            f"Cloudflare 挑战（cf-mitigated={challenge or 'html'}），无法判断"
            if challenge
            else "Cloudflare 挑战/HTML 拦截，无法判断"
        )
    else:
        detail = f"未识别的响应：HTTP {resp.status_code} {code or ''}".strip()

    status = Status.high if available is False else (Status.ok if available else Status.unknown)
    obs = Observation(
        key="official.region_gate",
        label="官方区域闸门",
        value={
            "available": available,
            "error_code": code,
            "message": message,
            "challenged": bool(resp.headers.get("cf-mitigated")),
            "status_code": resp.status_code,
        },
        status=status,
        source=source_from_response(
            "Claude region gate", SourceKind.official, REGION_GATE_URL, resp
        ),
        visibility="server",
        detail=detail,
        latency_ms=latency,
    )
    if available is None:
        return _region_fallback(http, obs)
    return obs


def _region_fallback(http: Http, obs: Observation) -> Observation:
    """Cross-check with the login redirect, which is stable and HTML-only."""
    try:
        resp = http.fetch(LOGIN_URL, follow_redirects=False)
    except Exception:
        return obs
    location = resp.headers.get("location", "")
    available: bool | None = None
    if 300 <= resp.status_code < 400 and "app-unavailable-in-region" in location:
        available = False
        detail = "登录页 302 到 app-unavailable-in-region，交叉验证为不支持地区"
    elif resp.status_code == 200:
        available = True
        detail = "登录页返回 200，交叉验证地区可用"
    if available is None:
        return obs
    obs.value = {**(obs.value or {}), "available": available, "fallback": "login_redirect"}
    obs.status = Status.high if available is False else Status.ok
    obs.detail = f"{obs.detail}；{detail}" if obs.detail else detail
    return obs


def check_status(http: Http, settings: Settings) -> tuple[ServiceStatus, Observation]:
    cached = cache_read(settings.cache_dir, "status_summary", STATUS_CACHE_TTL)
    resp = None
    if cached:
        data = cached
        status_source = Source(
            name="Claude Status (cached)",
            kind=SourceKind.official,
            url=STATUS_URL,
            confidence=Confidence.high,
        )
    else:
        try:
            resp = http.fetch(STATUS_URL, follow_redirects=True)
            resp.raise_for_status()
            data = resp.json()
            cache_write(settings.cache_dir, "status_summary", data)
            status_source = source_from_response(
                "Claude Status", SourceKind.official, STATUS_URL, resp
            )
        except Exception as exc:  # noqa: BLE001
            return (
                ServiceStatus(indicator="unknown", description="状态页不可达"),
                Observation(
                    key="official.status",
                    label="官方服务状态",
                    value={"indicator": "unknown"},
                    status=Status.unknown,
                    source=Source(
                        name="Claude Status",
                        kind=SourceKind.official,
                        url=STATUS_URL,
                        confidence=Confidence.medium,
                    ),
                    visibility="server",
                    detail="状态页不可达",
                    error=str(exc),
                ),
            )

    components = [
        StatusComponent(name=c.get("name", "?"), status=c.get("status", "unknown"))
        for c in data.get("components", [])
    ]
    relevant = [
        c
        for c in components
        if any(
            key in c.name.lower()
            for key in ("claude.ai", "claude api", "api.anthropic.com", "claude code")
        )
    ]
    indicator = (data.get("status") or {}).get("indicator", "unknown")
    description = (data.get("status") or {}).get("description", "")
    if relevant:
        ok = all(c.status == "operational" for c in relevant)
    else:
        # Component names may change; fall back to the page-level indicator.
        ok = indicator in {"none", "operational"}
    service = ServiceStatus(
        indicator=indicator,
        description=description,
        components=components,
        relevant_ok=ok,
    )
    obs = Observation(
        key="official.status",
        label="官方服务状态",
        value={
            "indicator": indicator,
            "description": description,
            "degraded": [c.name for c in relevant if c.status != "operational"],
        },
        status=Status.ok if ok else Status.high,
        source=status_source,
        visibility="server",
        detail=description or ("所有相关组件正常" if ok else "相关组件异常"),
    )
    return service, obs


def check_clock(http: Http) -> Observation:
    source = Source(
        name="HTTP Date header",
        kind=SourceKind.official,
        url=CLAUDE_URL,
        confidence=Confidence.medium,
    )
    try:
        resp = http.fetch(CLAUDE_URL, follow_redirects=False)
    except Exception as exc:  # noqa: BLE001
        return Observation(
            key="official.clock",
            label="系统时钟偏差",
            value=None,
            status=Status.unknown,
            source=source,
            visibility="local",
            detail="无法获取服务器时间",
            error=str(exc),
        )
    header = resp.headers.get("date")
    if not header:
        return Observation(
            key="official.clock",
            label="系统时钟偏差",
            value=None,
            status=Status.unknown,
            source=source,
            visibility="local",
            detail="响应缺少 Date 头",
        )
    try:
        server = parsedate_to_datetime(header)
        if server.tzinfo is None:
            server = server.replace(tzinfo=timezone.utc)
        offset = (datetime.now(timezone.utc) - server).total_seconds()
    except Exception:
        return Observation(
            key="official.clock",
            label="系统时钟偏差",
            value=None,
            status=Status.unknown,
            source=source,
            visibility="local",
            detail="Date 头无法解析",
        )
    abs_offset = abs(offset)
    status = Status.high if abs_offset > 300 else (Status.warn if abs_offset > 120 else Status.ok)
    return Observation(
        key="official.clock",
        label="系统时钟偏差",
        value=round(offset, 1),
        status=status,
        source=source,
        visibility="local",
        detail=f"本机与服务器相差 {offset:+.1f}s" + ("，OAuth/Cloudflare 可能失败" if abs_offset > 300 else ""),
    )


def check_reachability(http: Http) -> list[Observation]:
    results: list[Observation] = []
    for key, label, url in (
        ("reach.claude", "claude.ai 可达性", CLAUDE_URL),
        ("reach.api", "api.anthropic.com 可达性", API_URL),
    ):
        started = time.monotonic()
        try:
            resp = http.fetch(url, follow_redirects=False)
            latency = int((time.monotonic() - started) * 1000)
            ok = resp.status_code < 500
            results.append(
                Observation(
                    key=key,
                    label=label,
                    value={"status": resp.status_code, "latency_ms": latency},
                    status=Status.ok if ok else Status.warn,
                    source=source_from_response(label, SourceKind.official, url, resp),
                    visibility="server",
                    detail=f"HTTP {resp.status_code} · {latency}ms",
                    latency_ms=latency,
                )
            )
        except Exception as exc:  # noqa: BLE001
            latency = int((time.monotonic() - started) * 1000)
            results.append(
                Observation(
                    key=key,
                    label=label,
                    value={"status": None, "latency_ms": latency},
                    status=Status.unknown,
                    source=Source(name=label, kind=SourceKind.official, url=url),
                    visibility="server",
                    detail="连接失败",
                    error=str(exc),
                    latency_ms=latency,
                )
            )
    return results
