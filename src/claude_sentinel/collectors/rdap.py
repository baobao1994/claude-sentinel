"""RDAP lookups: authoritative allocation data without an API key."""

from __future__ import annotations

import ipaddress
from typing import Any

from claude_sentinel.collectors.base import (
    Http,
    cache_read,
    cache_write,
)
from claude_sentinel.config import Settings
from claude_sentinel.models import (
    Confidence,
    Observation,
    RdapInfo,
    Source,
    SourceKind,
    Status,
)

BOOTSTRAP = {
    4: "https://data.iana.org/rdap/ipv4.json",
    6: "https://data.iana.org/rdap/ipv6.json",
}
BOOTSTRAP_TTL = 30 * 24 * 3600


def _load_bootstrap(http: Http, settings: Settings, version: int) -> dict[str, Any]:
    url = BOOTSTRAP[version]
    cached = cache_read(settings.cache_dir, f"rdap_bootstrap_{version}", BOOTSTRAP_TTL)
    if cached:
        return cached
    resp = http.fetch(url, follow_redirects=True)
    resp.raise_for_status()
    data = resp.json()
    cache_write(settings.cache_dir, f"rdap_bootstrap_{version}", data)
    return data


def _select_base(data: dict[str, Any], ip: ipaddress._BaseAddress) -> str | None:
    best: tuple[int, str] | None = None
    for service in data.get("services", []):
        if not isinstance(service, list) or len(service) != 2:
            continue
        prefixes, urls = service
        if not urls:
            continue
        for prefix in prefixes:
            try:
                network = ipaddress.ip_network(prefix, strict=False)
            except ValueError:
                continue
            if ip.version == network.version and ip in network:
                if best is None or network.prefixlen > best[0]:
                    best = (network.prefixlen, urls[0])
    return best[1] if best else None


def lookup_rdap(ip: str, http: Http, settings: Settings) -> RdapInfo:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return RdapInfo(ip=ip, ok=False, error="invalid IP")
    try:
        bootstrap = _load_bootstrap(http, settings, addr.version)
        base = _select_base(bootstrap, addr)
    except Exception as exc:  # noqa: BLE001
        base = None
        bootstrap_error = str(exc)
    else:
        bootstrap_error = None

    if not base:
        base = "https://rdap.org"
    url = base.rstrip("/") + f"/ip/{ip}"

    try:
        resp = http.fetch(url, follow_redirects=True)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:  # noqa: BLE001
        return RdapInfo(
            ip=ip,
            ok=False,
            source_url=url,
            error=str(exc) or bootstrap_error,
        )

    abuse_email = None
    for entity in data.get("entities", []) or []:
        roles = entity.get("roles") or []
        if "abuse" not in roles:
            continue
        vcard = entity.get("vcardArray") or [None, []]
        try:
            fields = vcard[1]
        except (IndexError, TypeError):
            fields = []
        for field in fields:
            if not isinstance(field, list) or len(field) < 4:
                continue
            if field[0] == "email":
                abuse_email = field[3]
                break
        if abuse_email:
            break

    registration = None
    for event in data.get("events", []) or []:
        if event.get("eventAction") == "registration":
            registration = event.get("eventDate")
            break

    return RdapInfo(
        ip=ip,
        ok=True,
        network_name=data.get("name"),
        handle=data.get("handle"),
        start_address=data.get("startAddress"),
        end_address=data.get("endAddress"),
        registration=registration,
        country=data.get("country"),
        abuse_email=abuse_email,
        source_url=url,
    )


def rdap_observation(info: RdapInfo) -> Observation:
    if not info.ok:
        return Observation(
            key="ip.rdap",
            label="IP 段注册信息",
            value=None,
            status=Status.unknown,
            source=Source(
                name="RDAP",
                kind=SourceKind.registry,
                url=info.source_url,
                confidence=Confidence.medium,
            ),
            visibility="server",
            detail="RDAP 查询失败",
            error=info.error,
        )
    return Observation(
        key="ip.rdap",
        label="IP 段注册信息",
        value={
            "network": info.network_name,
            "handle": info.handle,
            "registration": info.registration,
            "abuse_email": info.abuse_email,
        },
        status=Status.ok,
        source=Source(
            name="RDAP (RIR)",
            kind=SourceKind.registry,
            url=info.source_url,
            http_status=200,
            confidence=Confidence.high,
        ),
        visibility="server",
        detail=f"{info.network_name or info.handle or '?'} · 注册 {info.registration or '?'}",
    )
