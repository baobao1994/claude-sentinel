from __future__ import annotations

import json
from pathlib import Path

import httpx

from claude_sentinel.collectors.base import Http
from claude_sentinel.collectors.official import (
    check_region_gate,
    load_regions,
    parse_supported_page,
)
from claude_sentinel.config import Settings, package_data_text
from claude_sentinel.models import Status


def _handler(responses: dict[str, httpx.Response]):
    def handle(request: httpx.Request) -> httpx.Response:
        for fragment, response in responses.items():
            if fragment in str(request.url):
                response.request = request
                return response
        return httpx.Response(404, text="not found", request=request)

    return handle


def _http(responses: dict[str, httpx.Response]) -> Http:
    return Http(transport=httpx.MockTransport(_handler(responses)))


def test_region_unavailable():
    http = _http(
        {
            "claude.ai/api/organizations": httpx.Response(
                403,
                json={
                    "type": "error",
                    "error": {
                        "type": "permission_error",
                        "message": "Claude isn't available in your region.",
                        "details": {
                            "error_code": "region_unavailable",
                            "error_visibility": "user_facing",
                        },
                    },
                },
            )
        }
    )
    obs = check_region_gate(http)
    assert obs.status == Status.high
    assert obs.value["available"] is False
    assert obs.value["error_code"] == "region_unavailable"


def test_region_available_but_unauthenticated():
    http = _http(
        {
            "claude.ai/api/organizations": httpx.Response(
                401,
                json={
                    "type": "error",
                    "error": {
                        "type": "permission_error",
                        "message": "Invalid authorization",
                        "details": {"error_code": "account_session_invalid"},
                    },
                },
            )
        }
    )
    obs = check_region_gate(http)
    assert obs.status == Status.ok
    assert obs.value["available"] is True


def test_cloudflare_challenge_falls_back_to_login_redirect():
    http = _http(
        {
            "claude.ai/api/organizations": httpx.Response(
                403,
                headers={"cf-mitigated": "challenge", "content-type": "text/html"},
                text="<html>challenge</html>",
            ),
            "claude.ai/login": httpx.Response(
                302,
                headers={"location": "https://claude.com/app-unavailable-in-region"},
            ),
        }
    )
    obs = check_region_gate(http)
    assert obs.value["available"] is False
    assert obs.value.get("fallback") == "login_redirect"


def test_parse_supported_page():
    aliases = json.loads(package_data_text("region_aliases.json"))["by_name"]
    names = [name for name in aliases if name and name[0].isupper()][:60]
    items = "".join(f"<li>{name}</li>" for name in names)
    html = f"""
    <html><body>
    <p>Effective November 12, 2026</p>
    <p>Countries and regions where we currently offer access:</p>
    <ul>{items}</ul>
    </body></html>
    """
    regions = parse_supported_page(html)
    assert len(regions.codes) >= 50
    assert regions.effective == "November 12, 2026"


def test_parse_supported_page_rejects_small_list():
    html = "<html><ul><li>Albania</li><li>Algeria</li></ul></html>"
    try:
        parse_supported_page(html)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")


def test_load_regions_falls_back_to_bundled(tmp_path: Path):
    http = Http(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(500, text="boom", request=request)
        )
    )
    settings = Settings(home=tmp_path)
    settings.ensure()
    regions, obs = load_regions(http, settings)
    assert len(regions.codes) >= 100
    assert obs.status == Status.warn
    assert "CN" not in regions.codes


def test_parse_multiple_lists_unions_countries():
    aliases = json.loads(package_data_text("region_aliases.json"))["by_name"]
    names = list(dict.fromkeys(n for n in aliases if n and n[0].isupper()))[:120]
    first = "".join(f"<li>{name}</li>" for name in names[:60])
    second = "".join(f"<li>{name}</li>" for name in names[60:])
    html = f"<html><body><ul>{first}</ul><ul>{second}</ul></body></html>"
    regions = parse_supported_page(html)
    assert len(regions.codes) >= 60
