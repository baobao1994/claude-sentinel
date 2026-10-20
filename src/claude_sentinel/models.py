"""Typed data model shared by collectors, rules, storage and renderers."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class StrEnum(str, Enum):
    """String enum whose ``str()`` is the value (py3.10 friendly)."""

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


class SourceKind(StrEnum):
    official = "official"
    registry = "registry"
    edge = "edge"
    third_party = "third_party"
    local = "local"
    self_report = "self_report"


class Visibility(StrEnum):
    server = "server"
    browser_js = "browser_js"
    local = "local"


class Confidence(StrEnum):
    high = "high"
    medium = "medium"
    low = "low"


class Status(StrEnum):
    ok = "ok"
    warn = "warn"
    high = "high"
    info = "info"
    unknown = "unknown"
    skipped = "skipped"


class Severity(StrEnum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Category(StrEnum):
    ip = "ip"
    stability = "stability"
    identity = "identity"
    client = "client"
    account = "account"
    behavior = "behavior"


class FixType(StrEnum):
    network = "network"
    locale = "locale"
    client = "client"
    account = "account"
    policy = "policy"
    none = "none"


class VerdictCode(StrEnum):
    ready = "ready"
    caution = "caution"
    high_caution = "high_caution"
    do_not_start = "do_not_start"
    blocked_region = "blocked_region"
    blocked_account = "blocked_account"
    blocked_service = "blocked_service"
    blocked_clock = "blocked_clock"
    unknown = "unknown"


class Source(BaseModel):
    name: str
    kind: SourceKind
    url: str | None = None
    retrieved_at: datetime = Field(default_factory=utcnow)
    http_status: int | None = None
    confidence: Confidence = Confidence.high
    note: str | None = None


class Observation(BaseModel):
    key: str
    label: str
    value: Any = None
    status: Status = Status.ok
    source: Source
    visibility: Visibility = Visibility.server
    confidence: Confidence = Confidence.high
    detail: str | None = None
    error: str | None = None
    latency_ms: int | None = None


class Finding(BaseModel):
    rule_id: str
    title: str
    category: Category
    severity: Severity
    status: Status
    points: float
    max_points: float
    evidence: str
    fix: str
    fix_type: FixType = FixType.none
    visibility: Visibility = Visibility.local
    confidence: Confidence = Confidence.medium
    sources: list[Source] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)


class CategoryScore(BaseModel):
    category: Category
    label: str
    weight: float
    earned: float
    possible: float
    total_possible: float
    score: float | None
    coverage: float


class Verdict(BaseModel):
    code: VerdictCode
    title: str
    headline: str
    reason: str
    can_start: bool | None
    account_note: str
    confidence: Confidence
    gate: str | None = None
    top_fixes: list[str] = Field(default_factory=list)


class IpIntel(BaseModel):
    provider: str
    ip: str
    ok: bool = True
    error: str | None = None
    country: str | None = None
    country_code: str | None = None
    city: str | None = None
    asn: str | None = None
    org: str | None = None
    isp: str | None = None
    is_proxy: bool | None = None
    is_vpn: bool | None = None
    is_tor: bool | None = None
    is_datacenter: bool | None = None
    is_mobile: bool | None = None
    is_abuser: bool | None = None
    risk: float | None = None
    asn_kind: str | None = None
    rpki_status: str | None = None
    is_residential: bool | None = None
    raw: dict[str, Any] = Field(default_factory=dict, exclude=True)


class IpConsensus(BaseModel):
    ip: str
    country: str | None = None
    country_code: str | None = None
    city: str | None = None
    asn: str | None = None
    org: str | None = None
    isp: str | None = None
    is_proxy: bool | None = None
    is_vpn: bool | None = None
    is_tor: bool | None = None
    is_datacenter: bool | None = None
    is_mobile: bool | None = None
    is_abuser: bool | None = None
    risk: float | None = None
    asn_kind: str | None = None  # backbone / isp / hosting / education ...
    rpki_status: str | None = None
    is_residential: bool | None = None
    providers_ok: int = 0
    providers_total: int = 0
    disagreements: list[str] = Field(default_factory=list)
    intel: list[IpIntel] = Field(default_factory=list)


class EdgeTrace(BaseModel):
    """One Cloudflare ``/cdn-cgi/trace`` view, per domain.

    The egress that matters is the one *Claude's own hostnames* see, not the
    one a generic Cloudflare domain sees: proxy rules are usually per-domain,
    so ``cloudflare.com`` and ``claude.ai`` can leave through different IPs.
    """

    key: str
    label: str
    url: str
    domain: str = ""
    ok: bool = False
    ip: str | None = None
    loc: str | None = None
    colo: str | None = None
    warp: str | None = None
    http: str | None = None
    tls: str | None = None
    error: str | None = None
    latency_ms: int | None = None


class RpkiValidation(BaseModel):
    """RPKI origin validation of the egress prefix (RIPEstat / Routinator)."""

    ip: str | None = None
    ok: bool = False
    prefix: str | None = None
    status: str | None = None  # valid / invalid_length / invalid_asn / unknown
    resource: str | None = None
    description: str | None = None
    error: str | None = None


class NetworkMode(BaseModel):
    """How traffic leaves the machine: TUN interface vs system proxy vs direct."""

    ipv4_interface: str | None = None
    ipv6_interface: str | None = None
    tun_interface: str | None = None
    tun_active: bool = False
    system_proxy_enabled: bool = False
    system_proxy_host: str | None = None
    system_proxy_port: int | None = None
    local_resolvers: list[str] = Field(default_factory=list)
    dns_via_tunnel: bool | None = None

    @property
    def summary(self) -> str:
        if self.tun_active:
            return f"TUN ({self.tun_interface})"
        if self.system_proxy_enabled:
            return "系统代理"
        return "直连"


class RuntimeProbe(BaseModel):
    """One runtime's view of the egress, measured from inside that runtime.

    A browser behind a system proxy and Node in a terminal can leave through
    different IPs; Claude Code runs on Node, so that difference matters.
    """

    runtime: str
    label: str
    available: bool = False
    ok: bool = False
    ip: str | None = None
    loc: str | None = None
    colo: str | None = None
    proxies_env: bool = False
    error: str | None = None


class RdapInfo(BaseModel):
    ip: str
    ok: bool = False
    network_name: str | None = None
    handle: str | None = None
    start_address: str | None = None
    end_address: str | None = None
    registration: str | None = None
    country: str | None = None
    abuse_email: str | None = None
    source_url: str | None = None
    error: str | None = None


class RegionList(BaseModel):
    codes: set[str] = Field(default_factory=set)
    names: dict[str, str] = Field(default_factory=dict)
    effective: str | None = None
    fetched_at: datetime = Field(default_factory=utcnow)
    source_url: str = "https://www.anthropic.com/supported-countries"
    scope: str = "all"
    stale: bool = False
    from_cache: bool = False
    unknown_names: list[str] = Field(default_factory=list)


class StatusComponent(BaseModel):
    name: str
    status: str


class ServiceStatus(BaseModel):
    indicator: str = "unknown"
    description: str = ""
    components: list[StatusComponent] = Field(default_factory=list)
    relevant_ok: bool = True
    source_url: str = "https://status.claude.com/api/v2/summary.json"


class AccountState(BaseModel):
    state: Literal[
        "active", "expired", "disabled", "region_blocked", "challenge", "unknown"
    ] = "unknown"
    method: str = "none"
    plan: str | None = None
    organization: str | None = None
    chat_capable: bool | None = None
    detail: str | None = None
    source: Source | None = None


class Profile(BaseModel):
    signup_country: str | None = None
    payment_country: str | None = None
    phone_country: str | None = None
    plan: str | None = None
    account_age_months: int | None = None
    shared: bool | None = None
    prior_ban: bool | None = None
    multiple_accounts: bool | None = None
    notes: str | None = None


class ClaudeCodeInfo(BaseModel):
    installed: bool = False
    version: str | None = None
    base_url: str | None = None
    base_url_kind: Literal["official", "third_party", "invalid", "unset"] = "unset"
    auth_modes: list[str] = Field(default_factory=list)
    settings_present: bool = False
    settings_keys: list[str] = Field(default_factory=list)
    config_present: bool = False
    config_size: int | None = None
    relay_hint: str | None = None


class LocalInfo(BaseModel):
    os: str = "unknown"
    arch: str = "unknown"
    timezone: str | None = None
    utc_offset: str | None = None
    locale: str | None = None
    languages: list[str] = Field(default_factory=list)
    fonts_cn: list[str] = Field(default_factory=list)
    browsers: list[str] = Field(default_factory=list)
    default_browser: str | None = None
    proxy_env: dict[str, str] = Field(default_factory=dict)
    system_proxy: str | None = None
    machine_fingerprint: str | None = None
    clock_offset_seconds: float | None = None


class WebRtcCandidate(BaseModel):
    candidate: str
    ip: str | None = None
    kind: str | None = None


class BrowserProbe(BaseModel):
    collected_at: datetime = Field(default_factory=utcnow)
    timezone: str | None = None
    utc_offset_minutes: int | None = None
    locale: str | None = None
    languages: list[str] = Field(default_factory=list)
    user_agent: str | None = None
    platform: str | None = None
    ua_mobile: bool | None = None
    screen: str | None = None
    device_pixel_ratio: float | None = None
    hardware_concurrency: int | None = None
    device_memory: float | None = None
    canvas_hash: str | None = None
    webgl_vendor: str | None = None
    webgl_renderer: str | None = None
    webgl_hash: str | None = None
    fonts: list[str] = Field(default_factory=list)
    webrtc: list[WebRtcCandidate] = Field(default_factory=list)
    egress_ip: str | None = None
    egress_country: str | None = None
    egress_colo: str | None = None
    warp: str | None = None
    dnt: str | None = None
    cookies_enabled: bool | None = None
    connection_type: str | None = None


class Drift(BaseModel):
    field: str
    label: str
    previous: str | None = None
    current: str | None = None
    severity: Severity = Severity.info
    changed: bool = False


class HistorySummary(BaseModel):
    is_baseline: bool = True
    runs: int = 0
    last_run_at: datetime | None = None
    last_verdict: str | None = None
    last_score: float | None = None
    last_ip: str | None = None
    last_ip_masked: str | None = None
    last_country: str | None = None
    last_asn: str | None = None
    last_timezone: str | None = None
    last_browser: str | None = None
    drift: list[Drift] = Field(default_factory=list)
    distinct_ips_24h: int = 0
    distinct_asns_24h: int = 0
    distinct_countries_24h: int = 0
    distinct_ips_7d: int = 0
    country_jumps_1h: int = 0


class EnvironmentSummary(BaseModel):
    ip: str | None = None
    ip_masked: str | None = None
    ipv6: str | None = None
    country: str | None = None
    country_code: str | None = None
    city: str | None = None
    asn: str | None = None
    org: str | None = None
    colo: str | None = None
    rpki: str | None = None
    asn_kind: str | None = None
    timezone: str | None = None
    locale: str | None = None
    languages: list[str] = Field(default_factory=list)
    browser: str | None = None
    os: str | None = None
    fingerprint: str | None = None
    account_state: str | None = None


class Report(BaseModel):
    schema_version: int = 1
    run_id: str
    started_at: datetime
    finished_at: datetime
    app_version: str
    rules_version: str
    verdict: Verdict
    score: float | None = None
    level: str = "unknown"
    #: How the score was arrived at: the weighted average, plus the severity
    #: floor that overrode it (if any). Shown so the number is auditable.
    score_basis: dict[str, Any] = Field(default_factory=dict)
    coverage: float = 0.0
    confidence: Confidence = Confidence.low
    categories: list[CategoryScore] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    observations: dict[str, Observation] = Field(default_factory=dict)
    environment: EnvironmentSummary = Field(default_factory=EnvironmentSummary)
    traces: list[EdgeTrace] = Field(default_factory=list)
    claude_egress: EdgeTrace | None = None
    rpki: RpkiValidation | None = None
    network_mode: NetworkMode | None = None
    runtimes: list[RuntimeProbe] = Field(default_factory=list)
    ip: IpConsensus | None = None
    ipv4: IpConsensus | None = None
    ipv6: IpConsensus | None = None
    rdap: RdapInfo | None = None
    behavior: dict[str, Any] | None = None
    regions: RegionList | None = None
    status: ServiceStatus | None = None
    account: AccountState | None = None
    profile: Profile | None = None
    client: ClaudeCodeInfo | None = None
    local: LocalInfo | None = None
    browser: BrowserProbe | None = None
    history: HistorySummary = Field(default_factory=HistorySummary)
    drift: list[Drift] = Field(default_factory=list)
    sources: list[Source] = Field(default_factory=list)
    disclaimers: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
