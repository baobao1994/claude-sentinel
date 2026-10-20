"""Small, dependency-free redaction helpers."""

from __future__ import annotations

import ipaddress
import re


def mask_ip(value: str | None) -> str | None:
    if not value:
        return value
    raw = value.strip().strip("[]").split("%")[0]
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        return value
    if ip.version == 4:
        parts = raw.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.*.*"
        return "***"
    # Keep the first two hextets, hide the rest.
    groups = raw.split(":")
    if len(groups) >= 3:
        return ":".join(groups[:2] + ["…"])
    return "…"


def mask_secret(value: str | None, keep: int = 4) -> str:
    if not value:
        return "***"
    if len(value) <= keep + 3:
        return "***"
    return f"***{value[-keep:]}"


def mask_cookie(cookie: str | None) -> str:
    if not cookie:
        return "***"
    names = []
    for part in cookie.split(";"):
        name = part.split("=", 1)[0].strip()
        if name:
            names.append(name)
    return "cookie(" + ", ".join(names[:6]) + ")"


_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_RE = re.compile(r"(?<![0-9A-Fa-f:])(?=[0-9A-Fa-f:]*:[0-9A-Fa-f:]*:)[0-9A-Fa-f:]{3,}(?![0-9A-Fa-f:])")


def _replace_ip(match: re.Match[str]) -> str:
    token = match.group(0)
    try:
        ipaddress.ip_address(token)
    except ValueError:
        return token
    return mask_ip(token) or token


def redact_text(text: str) -> str:
    """Mask IP addresses inside free-form strings (details, URLs, errors)."""
    text = _IPV4_RE.sub(_replace_ip, text)
    return _IPV6_RE.sub(_replace_ip, text)


_IP_KEYS = {
    "ip",
    "last_ip",
    "egress_ip",
    "ipv6",
    "full_ip",
    "browser_ip",
    "cli_ip",
}


def redact_ips_in_obj(value):
    """Recursively mask IP-looking fields in a JSON-like object."""
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if key == "raw" and isinstance(item, dict):
                continue
            if key in _IP_KEYS and isinstance(item, str):
                out[key] = mask_ip(item) or item
            else:
                out[key] = redact_ips_in_obj(item)
        return out
    if isinstance(value, list):
        return [redact_ips_in_obj(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value
