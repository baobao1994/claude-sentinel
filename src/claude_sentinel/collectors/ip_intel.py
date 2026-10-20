"""IP intelligence with multi-provider consensus and graceful degradation."""

from __future__ import annotations

import concurrent.futures
import os
import re
from typing import Any

from claude_sentinel.collectors.base import (
    Http,
    cache_read,
    cache_write,
)
from claude_sentinel.config import Settings
from claude_sentinel.models import (
    Confidence,
    IpConsensus,
    IpIntel,
    Observation,
    Source,
    SourceKind,
    Status,
)

IP_API = "http://ip-api.com/json/{ip}"
IPAPI_IS = "https://api.ipapi.is/?q={ip}"
IPINFO = "https://ipinfo.io/{ip}/json"
PROXYCHECK = "https://proxycheck.io/v2/{ip}?vpn=1&asn=1&risk=1"
ABUSEIPDB = "https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"

INTEL_CACHE_TTL = 24 * 3600


def _asn_parts(value: str | None) -> tuple[str | None, str | None]:
    if not value:
        return None, None
    m = re.match(r"^(AS\d+)\s*(.*)$", value.strip(), re.I)
    if m:
        return m.group(1).upper(), m.group(2).strip() or None
    return None, value.strip()


def _bool(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        low = value.strip().lower()
        if low in {"yes", "true", "1"}:
            return True
        if low in {"no", "false", "0"}:
            return False
    return None


def _provider_ip_api(http: Http, ip: str, timeout: float) -> IpIntel:
    fields = (
        "status,message,country,countryCode,regionName,city,isp,org,as,asname,"
        "proxy,hosting,mobile,query"
    )
    url = IP_API.format(ip=ip) + f"?fields={fields}"
    try:
        resp = http.fetch(url, timeout=timeout)
        data = resp.json()
    except Exception as exc:  # noqa: BLE001
        return IpIntel(provider="ip-api", ip=ip, ok=False, error=str(exc))
    if not isinstance(data, dict) or data.get("status") != "success":
        return IpIntel(
            provider="ip-api",
            ip=ip,
            ok=False,
            error=(data or {}).get("message") if isinstance(data, dict) else "bad response",
        )
    asn, org = _asn_parts(data.get("as") or data.get("asname"))
    return IpIntel(
        provider="ip-api",
        ip=ip,
        country=data.get("country"),
        country_code=data.get("countryCode"),
        city=data.get("city"),
        asn=asn,
        org=org or data.get("org") or data.get("isp"),
        isp=data.get("isp"),
        is_proxy=_bool(data.get("proxy")),
        is_datacenter=_bool(data.get("hosting")),
        is_mobile=_bool(data.get("mobile")),
        raw=data,
    )


def _provider_ipapi_is(http: Http, ip: str, timeout: float) -> IpIntel:
    url = IPAPI_IS.format(ip=ip)
    try:
        resp = http.fetch(url, timeout=timeout)
        data = resp.json()
    except Exception as exc:  # noqa: BLE001
        return IpIntel(provider="ipapi.is", ip=ip, ok=False, error=str(exc))
    if not isinstance(data, dict) or not data.get("ip"):
        return IpIntel(provider="ipapi.is", ip=ip, ok=False, error="bad response")
    asn, org = _asn_parts(data.get("asn"))
    company = data.get("company")
    if isinstance(company, dict):
        company_name = company.get("name")
        company_type = (company.get("type") or "").lower()
    else:
        company_name = company if isinstance(company, str) else None
        company_type = ""
    asn_obj = data.get("asn")
    asn_kind = None
    if isinstance(asn_obj, dict):
        asn_kind = asn_obj.get("type") or asn_obj.get("kind")
    rpki = data.get("rpki")
    rpki_status = None
    if isinstance(rpki, dict):
        rpki_status = rpki.get("status")
    datacenter = data.get("is_datacenter")
    return IpIntel(
        provider="ipapi.is",
        ip=ip,
        country=data.get("country"),
        country_code=data.get("country_code") or data.get("countryCode"),
        city=data.get("city"),
        asn=asn,
        org=company_name or org,
        is_proxy=_bool(data.get("is_proxy")),
        is_vpn=_bool(data.get("is_vpn")),
        is_tor=_bool(data.get("is_tor")),
        is_abuser=_bool(data.get("is_abuser")),
        is_datacenter=(
            _bool(datacenter) if datacenter is not None else (True if company_type in {"hosting", "datacenter"} else None)
        ),
        asn_kind=str(asn_kind).lower() if asn_kind else (company_type or None),
        rpki_status=str(rpki_status).lower() if rpki_status else None,
        is_residential=_bool(data.get("isResidential")),
        raw=data,
    )


def _provider_ipinfo(http: Http, ip: str, timeout: float) -> IpIntel:
    url = IPINFO.format(ip=ip)
    try:
        resp = http.fetch(url, timeout=timeout)
        data = resp.json()
    except Exception as exc:  # noqa: BLE001
        return IpIntel(provider="ipinfo", ip=ip, ok=False, error=str(exc))
    if not isinstance(data, dict) or data.get("bogon"):
        return IpIntel(provider="ipinfo", ip=ip, ok=False, error="bad response")
    asn, org = _asn_parts(data.get("org"))
    return IpIntel(
        provider="ipinfo",
        ip=ip,
        country=data.get("country"),
        country_code=data.get("country"),
        city=data.get("city"),
        asn=asn,
        org=org,
        raw=data,
    )


def _provider_proxycheck(http: Http, ip: str, timeout: float, key: str) -> IpIntel:
    url = PROXYCHECK.format(ip=ip) + f"&key={key}"
    try:
        resp = http.fetch(url, timeout=timeout)
        data = resp.json()
    except Exception as exc:  # noqa: BLE001
        return IpIntel(provider="proxycheck.io", ip=ip, ok=False, error=str(exc))
    if not isinstance(data, dict):
        return IpIntel(provider="proxycheck.io", ip=ip, ok=False, error="bad response")
    item = data.get(ip) or {}
    if not isinstance(item, dict):
        return IpIntel(provider="proxycheck.io", ip=ip, ok=False, error="bad response")
    proxy = _bool(item.get("proxy"))
    ptype = (item.get("type") or "").lower()
    risk = item.get("risk")
    return IpIntel(
        provider="proxycheck.io",
        ip=ip,
        country=item.get("country"),
        country_code=item.get("isocode"),
        city=item.get("city"),
        asn=(item.get("asn") or "").split(" ")[0] or None,
        org=item.get("provider"),
        is_proxy=proxy,
        is_vpn=True if ptype == "vpn" else None,
        is_tor=True if ptype == "tor" else None,
        is_datacenter=True if ptype in {"hosting", "business"} else None,
        risk=float(risk) if isinstance(risk, (int, float)) else None,
        raw=item,
    )


def _provider_abuseipdb(http: Http, ip: str, timeout: float, key: str) -> IpIntel:
    url = ABUSEIPDB.format(ip=ip)
    try:
        resp = http.fetch(
            url,
            timeout=timeout,
            headers={"Key": key, "Accept": "application/json"},
        )
        data = resp.json()
    except Exception as exc:  # noqa: BLE001
        return IpIntel(provider="abuseipdb", ip=ip, ok=False, error=str(exc))
    item = (data or {}).get("data") if isinstance(data, dict) else None
    if not isinstance(item, dict):
        return IpIntel(provider="abuseipdb", ip=ip, ok=False, error="bad response")
    usage = (item.get("usageType") or "").lower()
    score = item.get("abuseConfidenceScore")
    return IpIntel(
        provider="abuseipdb",
        ip=ip,
        country=item.get("countryCode"),
        country_code=item.get("countryCode"),
        isp=item.get("isp"),
        is_datacenter=True if "data center" in usage or "hosting" in usage else None,
        is_abuser=True if isinstance(score, (int, float)) and score >= 25 else None,
        risk=float(score) if isinstance(score, (int, float)) else None,
        raw=item,
    )


def _consensus(ip: str, intel: list[IpIntel]) -> IpConsensus:
    ok = [i for i in intel if i.ok]
    total = len(intel)
    if not ok:
        return IpConsensus(ip=ip, providers_ok=0, providers_total=total, intel=intel)

    def first(attr: str) -> Any:
        for item in ok:
            value = getattr(item, attr)
            if value not in (None, ""):
                return value
        return None

    def majority_bool(attr: str) -> tuple[bool | None, bool]:
        values = [getattr(i, attr) for i in ok if getattr(i, attr) is not None]
        if not values:
            return None, False
        if any(values):
            return True, not all(values)
        return False, False

    disagreements: list[str] = []
    flags: dict[str, bool | None] = {}
    for attr in ("is_proxy", "is_vpn", "is_tor", "is_datacenter", "is_mobile", "is_abuser"):
        value, disagree = majority_bool(attr)
        flags[attr] = value
        if disagree:
            disagreements.append(attr)

    countries = {i.country_code for i in ok if i.country_code}
    if len(countries) > 1:
        disagreements.append("country_code")

    risks = [i.risk for i in ok if i.risk is not None]
    kinds = [i.asn_kind for i in ok if i.asn_kind]
    rpkis = [i.rpki_status for i in ok if i.rpki_status]
    residential = [i.is_residential for i in ok if i.is_residential is not None]
    return IpConsensus(
        ip=ip,
        country=first("country"),
        country_code=first("country_code"),
        city=first("city"),
        asn=first("asn"),
        org=first("org"),
        isp=first("isp"),
        is_proxy=flags["is_proxy"],
        is_vpn=flags["is_vpn"],
        is_tor=flags["is_tor"],
        is_datacenter=flags["is_datacenter"],
        is_mobile=flags["is_mobile"],
        is_abuser=flags["is_abuser"],
        risk=max(risks) if risks else None,
        asn_kind=kinds[0] if kinds else None,
        rpki_status=rpkis[0] if rpkis else None,
        is_residential=any(residential) if residential else None,
        providers_ok=len(ok),
        providers_total=total,
        disagreements=disagreements,
        intel=intel,
    )


def lookup_ip(ip: str, http: Http, settings: Settings) -> IpConsensus:
    cache_key = f"ip_intel:{ip}"
    cached = cache_read(settings.cache_dir, cache_key, INTEL_CACHE_TTL)
    if cached:
        try:
            return IpConsensus.model_validate(cached)
        except Exception:
            pass

    timeout = min(6.0, settings.timeout)
    proxycheck_key = os.environ.get("PROXYCHECK_API_KEY")
    abuse_key = os.environ.get("ABUSEIPDB_API_KEY")

    providers: list[tuple[str, Any]] = [
        ("ip-api", lambda: _provider_ip_api(http, ip, timeout)),
        ("ipapi.is", lambda: _provider_ipapi_is(http, ip, timeout)),
        ("ipinfo", lambda: _provider_ipinfo(http, ip, timeout)),
    ]
    if proxycheck_key:
        providers.append(
            ("proxycheck.io", lambda: _provider_proxycheck(http, ip, timeout, proxycheck_key))
        )
    if abuse_key:
        providers.append(
            ("abuseipdb", lambda: _provider_abuseipdb(http, ip, timeout, abuse_key))
        )

    results: list[IpIntel] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(5, len(providers))) as pool:
        futures = {pool.submit(fn): name for name, fn in providers}
        for future in concurrent.futures.as_completed(futures):
            try:
                results.append(future.result())
            except Exception as exc:  # noqa: BLE001
                results.append(IpIntel(provider=futures[future], ip=ip, ok=False, error=str(exc)))

    consensus = _consensus(ip, results)
    cache_write(settings.cache_dir, cache_key, consensus.model_dump(mode="json"))
    return consensus


def consensus_observation(
    consensus: IpConsensus, key: str = "ip.consensus", label: str = "出口 IP 情报"
) -> Observation:
    status = Status.ok
    if consensus.providers_ok == 0:
        status = Status.unknown
    elif consensus.is_tor or consensus.is_abuser:
        status = Status.high
    elif consensus.is_proxy or consensus.is_vpn or consensus.is_datacenter:
        status = Status.warn

    flags = []
    for name in ("is_proxy", "is_vpn", "is_tor", "is_datacenter", "is_mobile", "is_abuser"):
        if getattr(consensus, name):
            flags.append(name.replace("is_", ""))
    return Observation(
        key=key,
        label=label,
        value={
            "ip": consensus.ip,
            "country_code": consensus.country_code,
            "country": consensus.country,
            "asn": consensus.asn,
            "org": consensus.org,
            "flags": flags,
            "risk": consensus.risk,
            "providers_ok": consensus.providers_ok,
            "providers_total": consensus.providers_total,
            "disagreements": consensus.disagreements,
        },
        status=status,
        source=Source(
            name="ip-api / ipapi.is / ipinfo"
            + (" / proxycheck" if "proxycheck.io" in [i.provider for i in consensus.intel] else "")
            + (" / AbuseIPDB" if "abuseipdb" in [i.provider for i in consensus.intel] else ""),
            kind=SourceKind.third_party,
            url="https://ip-api.com/",
            confidence=Confidence.high if consensus.providers_ok >= 2 else Confidence.medium,
        ),
        visibility="server",
        detail=(
            f"{consensus.ip} · {consensus.country_code or '?'} · {consensus.asn or '?'}"
            + (f" · {', '.join(flags)}" if flags else "")
            + (
                f" · 数据源 {consensus.providers_ok}/{consensus.providers_total}"
                if consensus.providers_ok < consensus.providers_total
                else ""
            )
        ),
    )
