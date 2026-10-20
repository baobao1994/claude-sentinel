from __future__ import annotations

import httpx

from claude_sentinel.collectors.account import probe_cookie, probe_oauth
from claude_sentinel.collectors.base import Http


def _http(handler) -> Http:
    return Http(transport=httpx.MockTransport(handler))


def test_cookie_active_with_chat():
    def handler(request):
        return httpx.Response(
            200,
            json=[{"name": "Personal", "capabilities": ["chat"]}],
            request=request,
        )

    state = probe_cookie("sk-ant-sid01-fake", _http(handler))
    assert state.state == "active"
    assert state.chat_capable is True


def test_cookie_invalid_session():
    def handler(request):
        return httpx.Response(
            403,
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

    state = probe_cookie("sk-ant-sid01-fake", _http(handler))
    assert state.state == "expired"


def test_cookie_region_block():
    def handler(request):
        return httpx.Response(
            403,
            json={
                "type": "error",
                "error": {
                    "type": "permission_error",
                    "message": "Claude isn't available in your region.",
                    "details": {"error_code": "region_unavailable"},
                },
            },
            request=request,
        )

    state = probe_cookie("sk-ant-sid01-fake", _http(handler))
    assert state.state == "region_blocked"


def test_cookie_cloudflare_challenge():
    def handler(request):
        return httpx.Response(
            403,
            headers={"cf-mitigated": "challenge"},
            text="<html>challenge</html>",
            request=request,
        )

    state = probe_cookie("sk-ant-sid01-fake", _http(handler))
    assert state.state == "challenge"


def test_oauth_active():
    def handler(request):
        return httpx.Response(
            200,
            json={
                "account": {"subscriptionType": "pro"},
                "organization": {"name": "Personal"},
                "subscriptionType": "pro",
            },
            request=request,
        )

    state = probe_oauth("sk-ant-oat01-fake", _http(handler))
    assert state.state == "active"
    assert state.plan == "pro"


def test_oauth_invalid():
    def handler(request):
        return httpx.Response(401, json={"error": {"message": "invalid"}}, request=request)

    state = probe_oauth("sk-ant-oat01-fake", _http(handler))
    assert state.state == "expired"


def test_oauth_disabled_message():
    def handler(request):
        return httpx.Response(
            403,
            json={"error": {"message": "This organization has been disabled."}},
            request=request,
        )

    state = probe_oauth("sk-ant-oat01-fake", _http(handler))
    assert state.state == "disabled"
