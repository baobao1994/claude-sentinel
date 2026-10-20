"""Optional account-state probe.

Read-only: one request, no retries, no message sending, no credential storage.
"""

from __future__ import annotations

import json
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from claude_sentinel.collectors.base import Http, parse_json, source_from_response
from claude_sentinel.models import AccountState, Confidence, Source, SourceKind

ORGS_URL = "https://claude.ai/api/organizations"
PROFILE_URL = "https://api.anthropic.com/api/oauth/profile"


def _source(url: str) -> Source:
    return Source(
        name="Claude account endpoint",
        kind=SourceKind.official,
        url=url,
        confidence=Confidence.high,
    )


def _cookie_value(cookie: str) -> str:
    cookie = cookie.strip()
    if "sessionKey=" in cookie:
        return cookie
    return f"sessionKey={cookie}"


def _error_fields(data: Any) -> tuple[str | None, str | None]:
    if not isinstance(data, dict):
        return None, None
    err = data.get("error") or {}
    if not isinstance(err, dict):
        return None, None
    code = (err.get("details") or {}).get("error_code")
    message = err.get("message")
    return code, message


def probe_cookie(cookie: str, http: Http, user_agent: str | None = None) -> AccountState:
    headers = {"Accept": "application/json", "Cache-Control": "no-cache"}
    if user_agent:
        headers["User-Agent"] = user_agent
    headers["Cookie"] = _cookie_value(cookie)
    try:
        resp = http.fetch(ORGS_URL, headers=headers)
    except Exception as exc:  # noqa: BLE001
        return AccountState(
            state="unknown",
            method="session_cookie",
            detail=f"请求失败：{type(exc).__name__}",
            source=_source(ORGS_URL),
        )

    if resp.headers.get("cf-mitigated"):
        return AccountState(
            state="challenge",
            method="session_cookie",
            detail="Cloudflare 挑战（cf-mitigated），无法判断账号状态",
            source=_source(ORGS_URL),
        )

    data = parse_json(resp)
    if resp.status_code == 200 and isinstance(data, list):
        chat = False
        org_name = None
        for org in data:
            if not isinstance(org, dict):
                continue
            caps = org.get("capabilities") or []
            if any("chat" in str(c) for c in caps):
                chat = True
            org_name = org.get("name") or org_name
        return AccountState(
            state="active",
            method="session_cookie",
            organization=org_name,
            chat_capable=chat,
            detail="会话有效" + ("" if chat else "；未发现 chat 能力"),
            source=_source(ORGS_URL),
        )

    code, message = _error_fields(data)
    message_low = (message or "").lower()
    if code == "region_unavailable" or "not available in your region" in message_low:
        state = "region_blocked"
    elif code == "account_session_invalid" or resp.status_code == 401:
        state = "expired"
    elif "disabled" in message_low:
        state = "disabled"
    elif resp.status_code == 429:
        state = "unknown"
    elif resp.status_code in {403, 503} and "text/html" in resp.headers.get("content-type", ""):
        state = "challenge"
    else:
        state = "unknown"

    return AccountState(
        state=state,  # type: ignore[arg-type]
        method="session_cookie",
        detail=f"HTTP {resp.status_code}" + (f" · {code}" if code else "") + (f" · {message}" if message else ""),
        source=source_from_response("Claude organizations", SourceKind.official, ORGS_URL, resp),
    )


def probe_oauth(token: str, http: Http, user_agent: str | None = None) -> AccountState:
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "anthropic-beta": "oauth-2025-04-20",
    }
    if user_agent:
        headers["User-Agent"] = user_agent
    try:
        resp = http.fetch(PROFILE_URL, headers=headers)
    except Exception as exc:  # noqa: BLE001
        return AccountState(
            state="unknown",
            method="oauth_token",
            detail=f"请求失败：{type(exc).__name__}",
            source=_source(PROFILE_URL),
        )

    data = parse_json(resp)
    if resp.status_code == 200 and isinstance(data, dict):
        account = data.get("account") if isinstance(data.get("account"), dict) else {}
        org = data.get("organization") if isinstance(data.get("organization"), dict) else {}
        plan = data.get("subscriptionType") or account.get("subscriptionType")
        caps = org.get("capabilities") if isinstance(org.get("capabilities"), list) else []
        chat = any("chat" in str(c) for c in caps) if caps else None
        return AccountState(
            state="active",
            method="oauth_token",
            plan=str(plan) if plan else None,
            organization=org.get("name"),
            chat_capable=chat,
            detail="OAuth 凭据有效",
            source=source_from_response("Claude OAuth profile", SourceKind.official, PROFILE_URL, resp),
        )

    message = ""
    if isinstance(data, dict):
        message = str((data.get("error") or {}).get("message") or "")
    low = message.lower()
    if resp.status_code == 401:
        state = "expired"
    elif "disabled" in low:
        state = "disabled"
    elif resp.status_code == 403 and ("not allowed" in low or "region" in low):
        state = "unknown"
    else:
        state = "unknown"
    return AccountState(
        state=state,  # type: ignore[arg-type]
        method="oauth_token",
        detail=f"HTTP {resp.status_code}" + (f" · {message}" if message else ""),
        source=source_from_response("Claude OAuth profile", SourceKind.official, PROFILE_URL, resp),
    )


def read_claude_code_token() -> tuple[str | None, AccountState | None]:
    """Read the local Claude Code OAuth token. Opt-in only; never logged."""
    if platform.system() == "Darwin":
        try:
            proc = subprocess.run(
                [
                    "security",
                    "find-generic-password",
                    "-s",
                    "Claude Code-credentials",
                    "-w",
                ],
                capture_output=True,
                text=True,
                timeout=6,
            )
        except (OSError, subprocess.SubprocessError):
            return None, None
        if proc.returncode != 0 or not proc.stdout.strip():
            return None, None
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return None, None
        oauth = data.get("claudeAiOauth") if isinstance(data, dict) else None
        if not isinstance(oauth, dict):
            return None, None
        token = oauth.get("accessToken") or oauth.get("access_token")
        expires = oauth.get("expiresAt")
        if expires:
            try:
                expires_dt = datetime.fromtimestamp(float(expires) / 1000, tz=timezone.utc)
                if expires_dt < datetime.now(timezone.utc):
                    return None, AccountState(
                        state="expired",
                        method="oauth_keychain",
                        detail="Claude Code OAuth 凭据已过期，需要重新登录",
                        source=_source(PROFILE_URL),
                    )
            except (TypeError, ValueError, OSError):
                pass
        return token if isinstance(token, str) else None, None

    path = Path.home() / ".claude" / ".credentials.json"
    if not path.exists():
        return None, None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None, None
    oauth = data.get("claudeAiOauth") if isinstance(data, dict) else None
    if isinstance(oauth, dict):
        token = oauth.get("accessToken") or oauth.get("access_token")
        return token if isinstance(token, str) else None, None
    return None, None
