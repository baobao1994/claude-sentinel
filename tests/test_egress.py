"""Per-domain egress: claude.ai's own view must drive the verdict.

The bug these tests lock down: a generic ``cloudflare.com`` probe said SG/clean
while ``claude.ai`` actually saw a CN residential IP, so the tool reported
"safe" for a path Claude would refuse.
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from claude_sentinel.collectors import network, rpki
from claude_sentinel.collectors.base import Http
from claude_sentinel.config import Settings
from claude_sentinel.models import EdgeTrace, HistorySummary, RegionList
from claude_sentinel.rules import evaluate
from claude_sentinel.rules.context import Context, GateInfo

REGIONS = RegionList(codes={"SG", "US", "JP", "GB"}, names={}, effective="test")


def _trace(key: str, domain: str, ip: str, loc: str) -> EdgeTrace:
    return EdgeTrace(
        key=key,
        label=f"{domain} 出口",
        url=f"https://{domain}/cdn-cgi/trace",
        domain=domain,
        ok=True,
        ip=ip,
        loc=loc,
        colo="LAX",
    )


def _ctx(traces, regions=REGIONS, rpki_info=None, ip=None) -> Context:
    return Context(
        settings=Settings(home=Path("/tmp/unused")),
        observations={},
        ip=ip,
        ipv4=None,
        ipv6=None,
        rdap=None,
        regions=regions,
        status=None,
        account=None,
        profile=None,
        client=None,
        local=None,
        browser=None,
        behavior=None,
        history=HistorySummary(),
        gate=GateInfo(),
        traces=traces,
        rpki=rpki_info,
    )


def _findings(ctx: Context) -> dict[str, object]:
    return {f.rule_id: f for f in evaluate(ctx)}


# ------------------------------------------------------------------ context
def test_claude_country_wins_over_generic_probe():
    ctx = _ctx(
        [
            _trace("trace.claude", "claude.ai", "203.0.113.250", "CN"),
            _trace("trace.cf", "cloudflare.com", "45.129.1.1", "SG"),
        ]
    )
    assert ctx.claude_country == "CN"
    assert ctx.claude_ip == "203.0.113.250"
    assert ctx.country_code == "CN"


def test_generic_trace_is_used_only_when_claude_names_are_unreachable():
    ctx = _ctx([_trace("trace.cf", "cloudflare.com", "45.129.1.1", "SG")])
    # Fallback keeps the report useful, but it is flagged as indirect.
    assert ctx.claude_egress is not None
    assert ctx.claude_trace_is_direct is False
    assert ctx.country_code == "SG"


def test_anthropic_hostname_is_preferred_over_generic_probe():
    ctx = _ctx(
        [
            _trace("trace.api", "api.anthropic.com", "45.129.1.1", "SG"),
            _trace("trace.cf", "cloudflare.com", "203.0.113.250", "CN"),
        ]
    )
    # api.anthropic.com outranks the generic probe, so CN must not win.
    assert ctx.country_code == "SG"
    assert ctx.claude_egress.key == "trace.api"


# ------------------------------------------------------------------- rules
def test_mismatch_between_domains_is_flagged_critical():
    ctx = _ctx(
        [
            _trace("trace.claude", "claude.ai", "203.0.113.250", "CN"),
            _trace("trace.cf", "cloudflare.com", "45.129.1.1", "SG"),
        ]
    )
    finding = _findings(ctx)["stability.egress_domain_mismatch"]
    assert finding.status == "high"
    assert finding.points > 0
    assert "CN" in finding.evidence and "SG" in finding.evidence


def test_consistent_domains_pass():
    ctx = _ctx(
        [
            _trace("trace.claude", "claude.ai", "45.129.1.1", "SG"),
            _trace("trace.cf", "cloudflare.com", "45.129.1.1", "SG"),
        ]
    )
    findings = _findings(ctx)
    assert findings["stability.egress_domain_mismatch"].status == "ok"
    assert findings["stability.egress_unsupported"].status == "ok"


def test_same_country_but_different_ip_is_a_soft_warning():
    ctx = _ctx(
        [
            _trace("trace.claude", "claude.ai", "45.129.1.1", "SG"),
            _trace("trace.cf", "cloudflare.com", "45.129.9.9", "SG"),
        ]
    )
    finding = _findings(ctx)["stability.egress_domain_mismatch"]
    assert finding.status == "warn"


def test_claude_egress_in_unsupported_country_is_flagged():
    ctx = _ctx([_trace("trace.claude", "claude.ai", "203.0.113.250", "CN")])
    finding = _findings(ctx)["stability.egress_unsupported"]
    assert finding.status == "high"
    assert "CN" in finding.evidence


def test_unsupported_rule_needs_the_region_list():
    ctx = _ctx(
        [_trace("trace.claude", "claude.ai", "203.0.113.250", "CN")],
        regions=None,
    )
    finding = _findings(ctx)["stability.egress_unsupported"]
    assert finding.status == "unknown"


def test_missing_claude_trace_degrades_but_stays_honest():
    ctx = _ctx([_trace("trace.cf", "cloudflare.com", "45.129.1.1", "SG")])
    findings = _findings(ctx)
    # One view only: cross-domain comparison is impossible, and the rule says so.
    mismatch = findings["stability.egress_domain_mismatch"]
    assert mismatch.status == "warn"
    assert "交叉验证" in mismatch.evidence
    # The unsupported-country conclusion must disclose the indirect basis.
    unsupported = findings["stability.egress_unsupported"]
    assert unsupported.status == "ok"


def test_indirect_evidence_downgrades_a_bad_country_to_warning():
    ctx = _ctx([_trace("trace.cf", "cloudflare.com", "203.0.113.250", "CN")])
    finding = _findings(ctx)["stability.egress_unsupported"]
    assert finding.status == "warn"
    assert "claude.ai 不可达" in finding.evidence


def test_no_trace_at_all_never_claims_safety():
    ctx = _ctx([])
    findings = _findings(ctx)
    assert findings["stability.egress_domain_mismatch"].status == "unknown"
    assert findings["stability.egress_unsupported"].status == "unknown"


# -------------------------------------------------------------- collectors
def _trace_handler(views: dict[str, tuple[str, str]]):
    def handler(request: httpx.Request) -> httpx.Response:
        host = request.url.host
        if host not in views:
            return httpx.Response(404, text="nope", request=request)
        ip, loc = views[host]
        body = f"fl=abc\nh={host}\nip={ip}\nts=1\nloc={loc}\ncolo=LAX\nwarp=off\nhttp=http/2\ntls=TLSv1.3\n"
        return httpx.Response(200, text=body, request=request)

    return handler


def test_collect_traces_reports_each_domain_separately():
    settings = Settings(home=Path("/tmp/unused"))
    http = Http(
        transport=httpx.MockTransport(
            _trace_handler(
                {
                    "claude.ai": ("203.0.113.250", "CN"),
                    "www.anthropic.com": ("203.0.113.250", "CN"),
                    "api.anthropic.com": ("45.129.1.1", "SG"),
                    "www.cloudflare.com": ("45.129.1.1", "SG"),
                }
            )
        )
    )
    del settings
    observations = network.collect_traces(http)
    assert [obs.key for obs in observations] == [key for key, _l, _u in network.TRACE_TARGETS]

    by_key = {obs.key: obs for obs in observations}
    assert by_key["trace.claude"].value["loc"] == "CN"
    assert by_key["trace.api"].value["loc"] == "SG"
    models = {trace.key: trace for trace in (network.trace_model(o) for o in observations)}
    assert models["trace.claude"].ok is True
    assert models["trace.claude"].domain == "claude.ai"


def test_collect_traces_survives_a_dead_domain():
    http = Http(
        transport=httpx.MockTransport(
            _trace_handler({"claude.ai": ("203.0.113.250", "CN")})
        )
    )
    observations = network.collect_traces(http)
    by_key = {obs.key: obs for obs in observations}
    assert by_key["trace.claude"].status == "ok"
    # A domain that 404s must degrade to "unknown", never crash the stage.
    assert by_key["trace.cf"].status == "unknown"
    assert network.trace_model(by_key["trace.cf"]).ok is False


# ------------------------------------------------------------------- RPKI
def _rpki_handler(prefix: str, asn: str, validity: str):
    def handler(request: httpx.Request) -> httpx.Response:
        if "prefix-overview" in str(request.url):
            return httpx.Response(
                200,
                json={"data": {"asns": [{"asn": int(asn), "holder": "Example"}], "resource": prefix}},
                request=request,
            )
        return httpx.Response(
            200,
            json={"data": {"validating_roas": [{"prefix": prefix, "origin": asn, "validity": validity}]}},
            request=request,
        )

    return handler


def test_rpki_resolves_prefix_then_validates(tmp_path: Path):
    settings = Settings(home=tmp_path)
    http = Http(transport=httpx.MockTransport(_rpki_handler("203.0.113.0/24", "64496", "valid")))
    result = rpki.lookup_rpki("203.0.113.250", http, settings)
    assert result is not None
    assert result.ok and result.status == "valid"
    assert result.prefix == "203.0.113.0/24"
    assert result.resource == "AS64496"


def test_rpki_invalid_is_reported_as_warning(tmp_path: Path):
    settings = Settings(home=tmp_path)
    http = Http(transport=httpx.MockTransport(_rpki_handler("45.129.1.0/24", "202656", "invalid_length")))
    result = rpki.lookup_rpki("45.129.1.1", http, settings)
    assert result is not None and result.ok
    assert result.status == "invalid_length"

    ctx = _ctx(
        [_trace("trace.claude", "claude.ai", "45.129.1.1", "SG")],
        rpki_info=result,
    )
    finding = _findings(ctx)["ip.rpki_invalid"]
    assert finding.status == "warn"


def test_rpki_is_cached_and_tolerates_failure(tmp_path: Path):
    settings = Settings(home=tmp_path)
    ok_http = Http(transport=httpx.MockTransport(_rpki_handler("203.0.113.0/24", "64496", "valid")))
    first = rpki.lookup_rpki("203.0.113.250", ok_http, settings)
    assert first.status == "valid"

    def boom(request):
        raise httpx.ConnectError("down", request=request)

    second = rpki.lookup_rpki("203.0.113.250", Http(transport=httpx.MockTransport(boom)), settings)
    assert second.status == "valid"  # served from cache

    third = rpki.lookup_rpki("203.0.113.99", Http(transport=httpx.MockTransport(boom)), settings)
    assert third.ok is False
    obs = rpki.rpki_observation(third)
    assert obs is not None and obs.status == "unknown"


def test_rpki_without_an_ip_is_skipped(tmp_path: Path):
    assert rpki.lookup_rpki(None, Http(transport=httpx.MockTransport(_rpki_handler("x", "1", "valid"))), Settings(home=tmp_path)) is None
    assert rpki.rpki_observation(None) is None


@pytest.mark.parametrize(
    "status,expected",
    [("valid", "ok"), ("invalid_length", "warn"), ("invalid_asn", "warn")],
)
def test_rpki_rule_status_mapping(tmp_path: Path, status: str, expected: str):
    from claude_sentinel.models import RpkiValidation

    info = RpkiValidation(ip="45.129.1.1", ok=True, prefix="45.129.1.0/24", status=status, resource="AS1")
    ctx = _ctx([_trace("trace.claude", "claude.ai", "45.129.1.1", "SG")], rpki_info=info)
    assert _findings(ctx)["ip.rpki_invalid"].status == expected
