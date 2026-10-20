"""Shared source descriptors for findings."""

from __future__ import annotations

from claude_sentinel.models import Confidence, Source, SourceKind

REGION_GATE = Source(
    name="Claude region gate",
    kind=SourceKind.official,
    url="https://claude.ai/api/organizations",
    confidence=Confidence.high,
)
SUPPORTED_REGIONS = Source(
    name="Anthropic Supported Regions Policy",
    kind=SourceKind.official,
    url="https://www.anthropic.com/supported-countries",
    confidence=Confidence.high,
)
STATUS_PAGE = Source(
    name="Claude Status",
    kind=SourceKind.official,
    url="https://status.claude.com/api/v2/summary.json",
    confidence=Confidence.high,
)
CLAUDE_HOME = Source(
    name="claude.ai",
    kind=SourceKind.official,
    url="https://claude.ai/",
    confidence=Confidence.high,
)
IP_API = Source(
    name="ip-api.com",
    kind=SourceKind.third_party,
    url="https://ip-api.com/",
    confidence=Confidence.medium,
)
IPAPI_IS = Source(
    name="ipapi.is",
    kind=SourceKind.third_party,
    url="https://ipapi.is/",
    confidence=Confidence.medium,
)
PROXYCHECK = Source(
    name="proxycheck.io",
    kind=SourceKind.third_party,
    url="https://proxycheck.io/",
    confidence=Confidence.medium,
)
ABUSEIPDB = Source(
    name="AbuseIPDB",
    kind=SourceKind.third_party,
    url="https://www.abuseipdb.com/",
    confidence=Confidence.medium,
)
RDAP = Source(
    name="RDAP (RIR)",
    kind=SourceKind.registry,
    url="https://rdap.org/",
    confidence=Confidence.high,
)
RIPESTAT = Source(
    name="RIPEstat RPKI validation",
    kind=SourceKind.registry,
    url="https://stat.ripe.net/",
    confidence=Confidence.high,
)
TRACE_CLAUDE = Source(
    name="claude.ai /cdn-cgi/trace",
    kind=SourceKind.edge,
    url="https://claude.ai/cdn-cgi/trace",
    confidence=Confidence.high,
)
TRACE_CF = Source(
    name="cloudflare.com /cdn-cgi/trace",
    kind=SourceKind.edge,
    url="https://www.cloudflare.com/cdn-cgi/trace",
    confidence=Confidence.high,
)
EDNS = Source(
    name="edns.ip-api.com",
    kind=SourceKind.third_party,
    url="https://edns.ip-api.com/",
    confidence=Confidence.medium,
)
LOCAL = Source(
    name="Local environment",
    kind=SourceKind.local,
    url=None,
    confidence=Confidence.medium,
)
CLIENT = Source(
    name="Claude Code local config",
    kind=SourceKind.local,
    url="https://code.claude.com/docs/",
    confidence=Confidence.high,
)
ACCOUNT = Source(
    name="Claude account endpoint",
    kind=SourceKind.official,
    url="https://claude.ai/api/organizations",
    confidence=Confidence.high,
)
POLICY = Source(
    name="Anthropic Usage Policy / Consumer Terms",
    kind=SourceKind.official,
    url="https://www.anthropic.com/legal/consumer-terms",
    confidence=Confidence.high,
)
