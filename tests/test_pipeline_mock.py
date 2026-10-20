from __future__ import annotations

import json
from datetime import datetime, timezone
from email.utils import format_datetime
from pathlib import Path

import httpx

from claude_sentinel.collectors import network
from claude_sentinel.collectors.base import Http
from claude_sentinel.config import Settings, package_data_text
from claude_sentinel.models import ClaudeCodeInfo
from claude_sentinel.pipeline import run_scan


def _supported_html() -> str:
    data = json.loads(package_data_text("regions.json"))
    items = "".join(f"<li>{c['name']}</li>" for c in data["countries"])
    return f"<html><body><p>Effective November 12, 2026</p><p>Countries and regions where we currently offer access:</p><ul>{items}</ul></body></html>"


def _handler(request: httpx.Request) -> httpx.Response:
    url = str(request.url)
    if "claude.ai/api/organizations" in url:
        return httpx.Response(
            401,
            json={
                "type": "error",
                "error": {
                    "type": "permission_error",
                    "message": "Invalid authorization",
                    "details": {"error_code": "account_session_invalid"},
                },
            },
            request=request,
        )
    if url.endswith("claude.ai/login"):
        return httpx.Response(200, text="login", request=request)
    if "supported-countries" in url:
        return httpx.Response(200, text=_supported_html(), request=request)
    if "status.claude.com" in url:
        return httpx.Response(
            200,
            json={
                "status": {"indicator": "none", "description": "All Systems Operational"},
                "components": [
                    {"name": "claude.ai", "status": "operational"},
                    {"name": "Claude API", "status": "operational"},
                    {"name": "Claude Code", "status": "operational"},
                ],
            },
            request=request,
        )
    if url == "https://claude.ai/":
        return httpx.Response(200, headers={"date": format_datetime(datetime.now(timezone.utc), usegmt=True)}, request=request)
    if url == "https://api.anthropic.com/":
        return httpx.Response(403, text="forbidden", request=request)
    if "cloudflare.com/cdn-cgi/trace" in url:
        return httpx.Response(200, text="ip=203.0.113.9\nloc=US\ncolo=LAX\nwarp=off\ntls=TLSv1.3\n", request=request)
    # Per-domain traces: in this fixture every hostname agrees (US).
    for host in (
        "claude.ai/cdn-cgi/trace",
        "www.anthropic.com/cdn-cgi/trace",
        "api.anthropic.com/cdn-cgi/trace",
    ):
        if url.endswith(host):
            return httpx.Response(
                200,
                text="ip=203.0.113.9\nloc=US\ncolo=LAX\nwarp=off\ntls=TLSv1.3\n",
                request=request,
            )
    if "stat.ripe.net" in url:
        if "prefix-overview" in url:
            return httpx.Response(
                200,
                json={
                    "data": {
                        "asns": [{"asn": 12345, "holder": "Example"}],
                        "resource": "203.0.113.0/24",
                    }
                },
                request=request,
            )
        return httpx.Response(
            200,
            json={
                "data": {
                    "validating_roas": [
                        {"prefix": "203.0.113.0/24", "origin": "12345", "validity": "valid"}
                    ]
                }
            },
            request=request,
        )
    if "edns.ip-api.com" in url:
        return httpx.Response(200, json={"dns": {"ip": "8.8.8.8", "geo": "United States - Google"}}, request=request)
    if "ip-api.com" in url:
        return httpx.Response(
            200,
            json={
                "status": "success",
                "country": "United States",
                "countryCode": "US",
                "city": "Los Angeles",
                "isp": "Example ISP",
                "org": "Example",
                "as": "AS12345 Example",
                "proxy": False,
                "hosting": False,
                "mobile": False,
                "query": "203.0.113.9",
            },
            request=request,
        )
    if "api.ipapi.is" in url:
        return httpx.Response(
            200,
            json={"ip": "203.0.113.9", "country": "United States", "company": "Example", "asn": "AS12345 Example", "city": "Los Angeles"},
            request=request,
        )
    if "ipinfo.io" in url:
        return httpx.Response(200, json={"ip": "203.0.113.9", "country": "US", "city": "Los Angeles", "org": "AS12345 Example"}, request=request)
    if "data.iana.org/rdap" in url:
        return httpx.Response(200, json={"services": [[["0.0.0.0/0"], ["https://rdap.example"]]]}, request=request)
    if "rdap.example" in url:
        return httpx.Response(404, json={"error": "not found"}, request=request)
    return httpx.Response(404, text="not found", request=request)


def test_pipeline_with_mocked_us_path(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(network, "_curl_trace", lambda family, proxy=None: {"ip": "203.0.113.9", "loc": "US", "colo": "LAX", "warp": "off"})
    monkeypatch.setattr(
        "claude_sentinel.pipeline.claude_code.collect_claude_code",
        lambda: (
            ClaudeCodeInfo(
                installed=True,
                version="2.1.273",
                base_url_kind="official",
                auth_modes=["oauth_file"],
            ),
            [],
        ),
    )
    settings = Settings(home=tmp_path, timeout=3, ip_intel=True)
    http = Http(transport=httpx.MockTransport(_handler))
    report = run_scan(settings, http=http)
    assert report.environment.country_code == "US"
    assert report.regions is not None and len(report.regions.codes) > 100
    assert report.ip is not None and report.ip.providers_ok >= 2
    assert report.score is not None
    assert report.verdict.code.value != "blocked_region"
    # This fixture is a CN machine (Asia/Shanghai, CN resolver) behind a US
    # egress, with a terminal that bypasses the system proxy. That is a
    # genuinely bad environment, so the verdict must reflect it rather than
    # being averaged down to "caution".
    assert report.verdict.code.value in {"high_caution", "do_not_start"}
    assert any(f.rule_id == "stability.runtime_split" and f.status == "high" for f in report.findings)
