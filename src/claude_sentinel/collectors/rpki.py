"""RPKI origin validation via RIPEstat (public, no API key).

``rpki-validation`` only accepts an ASN, so the lookup is two steps:
resolve the egress IP to its origin ASN + prefix (``prefix-overview``), then
ask whether that origin is authorised for that prefix.

An invalid result is a fact about the route (mis-configured or hijackable
block), not a score, so it feeds the rules as evidence.
"""

from __future__ import annotations

from claude_sentinel.collectors.base import Http, cache_read, cache_write
from claude_sentinel.config import Settings
from claude_sentinel.models import (
    Confidence,
    Observation,
    RpkiValidation,
    Source,
    SourceKind,
    Status,
)

RIPESTAT_BASE = "https://stat.ripe.net/data"
CACHE_TTL = 24 * 3600

STATUS_ZH = {
    "valid": "有效",
    "invalid_length": "前缀长度不合法",
    "invalid_asn": "起源 ASN 不合法",
    "invalid": "无效",
    "unknown": "未知",
}


def _label(status: str | None) -> str:
    if not status:
        return "无法判断"
    return STATUS_ZH.get(status, status)


def resolve_prefix(http: Http, ip: str) -> tuple[str | None, str | None]:
    """Return ``(prefix, asn)`` for an IP using RIPEstat prefix-overview."""
    resp = http.fetch(
        f"{RIPESTAT_BASE}/prefix-overview/data.json",
        params={"resource": ip},
        follow_redirects=True,
    )
    resp.raise_for_status()
    data = resp.json().get("data") or {}
    asns = data.get("asns") or []
    asn = None
    if asns and isinstance(asns[0], dict) and asns[0].get("asn") is not None:
        asn = str(asns[0]["asn"])
    prefix = None
    resources = data.get("resource")
    if isinstance(resources, str) and "/" in resources:
        prefix = resources
    elif isinstance(resources, list) and resources:
        first = resources[0]
        if isinstance(first, str):
            prefix = first
        elif isinstance(first, dict):
            prefix = first.get("prefix")
    return prefix, asn


def lookup_rpki(ip: str | None, http: Http, settings: Settings) -> RpkiValidation | None:
    """Validate the egress prefix. ``None`` only when there is no IP at all."""
    if not ip:
        return None
    cached = cache_read(settings.cache_dir, f"rpki_{ip}", CACHE_TTL)
    if isinstance(cached, dict):
        try:
            return RpkiValidation.model_validate(cached)
        except Exception:  # noqa: BLE001 - a stale cache must not break a scan
            pass

    try:
        prefix, asn = resolve_prefix(http, ip)
        if not prefix or not asn:
            result = RpkiValidation(ip=ip, ok=False, error="无法由 IP 解析出前缀或 ASN")
        else:
            resp = http.fetch(
                f"{RIPESTAT_BASE}/rpki-validation/data.json",
                params={"resource": f"AS{asn}", "prefix": prefix},
                follow_redirects=True,
            )
            resp.raise_for_status()
            data = resp.json().get("data") or {}
            roas = data.get("validating_roas") or []
            first = roas[0] if roas and isinstance(roas[0], dict) else {}
            result = RpkiValidation(
                ip=ip,
                ok=True,
                prefix=prefix,
                status=str(first.get("validity") or data.get("status") or "unknown"),
                resource=f"AS{asn}",
            )
    except Exception as exc:  # noqa: BLE001
        result = RpkiValidation(ip=ip, ok=False, error=str(exc)[:180])
    try:
        cache_write(settings.cache_dir, f"rpki_{ip}", result.model_dump(mode="json"))
    except OSError:
        pass
    return result


def rpki_observation(info: RpkiValidation | None) -> Observation | None:
    if info is None:
        return None
    source = Source(
        name="RIPEstat RPKI validation",
        kind=SourceKind.registry,
        url=f"{RIPESTAT_BASE}/rpki-validation/data.json",
        confidence=Confidence.high,
    )
    if not info.ok:
        return Observation(
            key="rpki.prefix",
            label="RPKI 前缀校验",
            value=None,
            status=Status.unknown,
            source=source,
            visibility="server",
            detail="RPKI 校验数据不可达",
            error=info.error,
        )
    status = info.status or "unknown"
    return Observation(
        key="rpki.prefix",
        label="RPKI 前缀校验",
        value={"prefix": info.prefix, "status": status, "origin": info.resource},
        status=Status.ok if status == "valid" else Status.warn,
        source=source,
        visibility="server",
        detail=f"{info.prefix or '?'} · {_label(status)}",
    )
