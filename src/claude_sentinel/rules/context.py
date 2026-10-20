"""Rule evaluation context and small shared helpers."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from claude_sentinel.config import Settings
from claude_sentinel.models import (
    AccountState,
    BrowserProbe,
    ClaudeCodeInfo,
    EdgeTrace,
    HistorySummary,
    IpConsensus,
    LocalInfo,
    NetworkMode,
    Observation,
    Profile,
    RdapInfo,
    RegionList,
    RpkiValidation,
    RuntimeProbe,
    ServiceStatus,
    utcnow,
)


def _is_private_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value.strip().strip("[]"))
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast


@dataclass
class GateInfo:
    region_available: bool | None = None
    region_error_code: str | None = None
    region_detail: str | None = None
    status_ok: bool | None = None
    clock_offset: float | None = None


@dataclass
class Context:
    settings: Settings
    observations: dict[str, Observation]
    ip: IpConsensus | None
    ipv4: IpConsensus | None
    ipv6: IpConsensus | None
    rdap: RdapInfo | None
    regions: RegionList | None
    status: ServiceStatus | None
    account: AccountState | None
    profile: Profile | None
    client: ClaudeCodeInfo | None
    local: LocalInfo | None
    browser: BrowserProbe | None
    behavior: dict[str, Any] | None
    history: HistorySummary
    gate: GateInfo
    traces: list[EdgeTrace] = field(default_factory=list)
    rpki: RpkiValidation | None = None
    network_mode: NetworkMode | None = None
    runtimes: list[RuntimeProbe] = field(default_factory=list)
    now: datetime = field(default_factory=utcnow)

    @property
    def node_runtime(self) -> RuntimeProbe | None:
        """Claude Code's own runtime: the path that matters most in a terminal."""
        for probe in self.runtimes:
            if probe.runtime == "node" and probe.ok:
                return probe
        return None

    @property
    def webrtc_public_ips(self) -> list[str]:
        """Non-private IPs leaked by WebRTC (STUN/reflexive candidates)."""
        if not self.browser:
            return []
        out: list[str] = []
        for candidate in self.browser.webrtc:
            if not candidate.ip or candidate.kind == "host":
                continue
            if _is_private_ip(candidate.ip):
                continue
            if candidate.ip not in out:
                out.append(candidate.ip)
        return out

    @property
    def claude_egress(self) -> EdgeTrace | None:
        """The best available view of what Claude sees.

        ``claude.ai`` is authoritative. If its trace is unreachable (some
        proxies block that path), fall back through the other Anthropic
        hostnames and finally the generic Cloudflare probe — the report always
        records which domain answered, so a fallback is never silent.
        """
        for key in ("trace.claude", "trace.anthropic", "trace.api", "trace.cf"):
            for trace in self.traces:
                if trace.key == key and trace.ok and trace.loc:
                    return trace
        return None

    @property
    def claude_trace_is_direct(self) -> bool:
        trace = self.claude_egress
        return bool(trace and trace.key == "trace.claude")

    @property
    def claude_country(self) -> str | None:
        trace = self.claude_egress
        return trace.loc.upper() if trace and trace.loc else None

    @property
    def claude_ip(self) -> str | None:
        trace = self.claude_egress
        return trace.ip if trace else None

    @property
    def ok_traces(self) -> list[EdgeTrace]:
        return [trace for trace in self.traces if trace.ok and trace.loc]

    @property
    def trace_by_key(self) -> dict[str, EdgeTrace]:
        return {trace.key: trace for trace in self.traces}

    @property
    def country_code(self) -> str | None:
        # Prefer what claude.ai sees over any generic/third-party view.
        claude = self.claude_country
        if claude:
            return claude
        if self.ip and self.ip.country_code:
            return self.ip.country_code.upper()
        edge = self.observations.get("net.edge")
        if edge and isinstance(edge.value, dict) and edge.value.get("loc"):
            return str(edge.value["loc"]).upper()
        return None

    @property
    def country_name(self) -> str | None:
        if self.ip and self.ip.country:
            return self.ip.country
        return None

    @property
    def browser_country(self) -> str | None:
        if self.browser and self.browser.egress_country:
            return self.browser.egress_country.upper()
        return None

    def obs(self, key: str) -> Observation | None:
        return self.observations.get(key)

    def drift(self, field_name: str):
        for item in self.history.drift:
            if item.field == field_name:
                return item
        return None


CN_TIMEZONES = {"Asia/Shanghai", "Asia/Urumqi", "PRC", "Asia/Chongqing"}
GREATER_CHINA = {"CN", "TW", "HK", "MO"}

TIMEZONE_COUNTRY = {
    "Asia/Shanghai": "CN",
    "Asia/Chongqing": "CN",
    "Asia/Urumqi": "CN",
    "Asia/Harbin": "CN",
    "Asia/Hong_Kong": "HK",
    "Asia/Macau": "MO",
    "Asia/Taipei": "TW",
    "Asia/Tokyo": "JP",
    "Asia/Seoul": "KR",
    "Asia/Singapore": "SG",
    "Asia/Kuala_Lumpur": "MY",
    "Asia/Bangkok": "TH",
    "Asia/Jakarta": "ID",
    "Asia/Manila": "PH",
    "Asia/Ho_Chi_Minh": "VN",
    "Asia/Kolkata": "IN",
    "Asia/Dubai": "AE",
    "Asia/Riyadh": "SA",
    "Asia/Jerusalem": "IL",
    "Europe/London": "GB",
    "Europe/Dublin": "IE",
    "Europe/Paris": "FR",
    "Europe/Berlin": "DE",
    "Europe/Amsterdam": "NL",
    "Europe/Zurich": "CH",
    "Europe/Madrid": "ES",
    "Europe/Rome": "IT",
    "Europe/Warsaw": "PL",
    "Europe/Stockholm": "SE",
    "Europe/Oslo": "NO",
    "Europe/Copenhagen": "DK",
    "Europe/Helsinki": "FI",
    "Europe/Lisbon": "PT",
    "Europe/Vienna": "AT",
    "Europe/Brussels": "BE",
    "Europe/Prague": "CZ",
    "Europe/Budapest": "HU",
    "Europe/Bucharest": "RO",
    "Europe/Athens": "GR",
    "Europe/Istanbul": "TR",
    "America/New_York": "US",
    "America/Chicago": "US",
    "America/Denver": "US",
    "America/Los_Angeles": "US",
    "America/Toronto": "CA",
    "America/Vancouver": "CA",
    "America/Mexico_City": "MX",
    "America/Sao_Paulo": "BR",
    "Australia/Sydney": "AU",
    "Australia/Melbourne": "AU",
    "Pacific/Auckland": "NZ",
    "Africa/Johannesburg": "ZA",
}

CN_BROWSER_HINTS = (
    "360",
    "QQ",
    "搜狗",
    "UC",
    "夸克",
    "百度",
    "猎豹",
    "Maxthon",
)


def tz_country(tz: str | None) -> str | None:
    if not tz:
        return None
    if tz in TIMEZONE_COUNTRY:
        return TIMEZONE_COUNTRY[tz]
    for name, code in TIMEZONE_COUNTRY.items():
        if tz.startswith(name + "/"):
            return code
    return None
