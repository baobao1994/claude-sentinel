"""Claude Code client posture: version, endpoint override and auth shape."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlsplit

from claude_sentinel.models import (
    ClaudeCodeInfo,
    Confidence,
    Observation,
    Source,
    SourceKind,
    Status,
    Visibility,
)


def _version_tuple(value: str | None) -> tuple[int, ...]:
    if not value:
        return ()
    return tuple(int(x) for x in re.findall(r"\d+", value)[:3])


def is_old_marker_version(version: str | None) -> bool:
    """Versions 2.1.91 .. 2.1.196 contained the prompt-marker logic."""
    parsed = _version_tuple(version)
    if len(parsed) < 3:
        return False
    return (2, 1, 91) <= parsed < (2, 1, 197)


def classify_base_url(value: str | None) -> tuple[str, str | None]:
    if not value:
        return "unset", None
    try:
        parts = urlsplit(value)
    except Exception:
        return "invalid", None
    host = (parts.hostname or "").lower()
    if not host:
        return "invalid", None
    if host == "api.anthropic.com" or host.endswith(".anthropic.com") or host == "anthropic.com":
        return "official", host
    return "third_party", host


def _read_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def collect_claude_code() -> tuple[ClaudeCodeInfo, list[Observation]]:
    home = Path.home()
    claude_dir = home / ".claude"
    settings_path = claude_dir / "settings.json"
    config_path = home / ".claude.json"

    binary = shutil.which("claude")
    version = None
    if binary:
        try:
            proc = subprocess.run(
                [binary, "--version"], capture_output=True, text=True, timeout=6
            )
            text = (proc.stdout or proc.stderr).strip()
            match = re.search(r"\d+\.\d+\.\d+", text)
            version = match.group(0) if match else None
        except (OSError, subprocess.SubprocessError):
            pass

    settings = _read_json(settings_path)
    settings_keys = sorted(settings.keys())
    env_section = settings.get("env") if isinstance(settings.get("env"), dict) else {}
    for key in env_section:
        settings_keys.append(f"env.{key}")

    base_url = os.environ.get("ANTHROPIC_BASE_URL") or env_section.get("ANTHROPIC_BASE_URL")
    base_kind, host = classify_base_url(base_url)

    auth_modes = []
    if os.environ.get("ANTHROPIC_API_KEY") or env_section.get("ANTHROPIC_API_KEY"):
        auth_modes.append("api_key")
    if os.environ.get("ANTHROPIC_AUTH_TOKEN") or env_section.get("ANTHROPIC_AUTH_TOKEN"):
        auth_modes.append("auth_token")
    if (claude_dir / ".credentials.json").exists():
        auth_modes.append("oauth_file")

    info = ClaudeCodeInfo(
        installed=bool(binary),
        version=version,
        base_url=base_url,
        base_url_kind=base_kind,  # type: ignore[arg-type]
        auth_modes=auth_modes,
        settings_present=settings_path.exists(),
        settings_keys=sorted(set(settings_keys)),
        config_present=config_path.exists(),
        config_size=config_path.stat().st_size if config_path.exists() else None,
        relay_hint=host if base_kind == "third_party" else None,
    )

    source = Source(name="Claude Code local config", kind=SourceKind.local, confidence=Confidence.high)
    observations = [
        Observation(
            key="client.claude_code",
            label="Claude Code",
            value={"installed": info.installed, "version": version},
            status=Status.ok if info.installed else Status.skipped,
            source=source,
            visibility=Visibility.local,
            detail=f"v{version}" if version else ("未安装" if not info.installed else "版本未知"),
        ),
        Observation(
            key="client.base_url",
            label="API 端点",
            value={
                "base_url": base_url,
                "kind": base_kind,
                "host": host,
                "old_marker_version": is_old_marker_version(version),
            },
            status=(
                Status.high
                if base_kind == "third_party"
                else (Status.warn if base_kind == "invalid" else Status.info)
            ),
            source=source,
            visibility=Visibility.server,
            detail=(
                f"第三方中转：{host}"
                if base_kind == "third_party"
                else ("未设置（使用官方默认）" if base_kind == "unset" else f"官方：{host or '?'}")
            ),
        ),
        Observation(
            key="client.auth",
            label="认证形态",
            value=auth_modes,
            status=Status.warn if len(set(auth_modes)) > 1 else Status.info,
            source=source,
            visibility=Visibility.server,
            detail=", ".join(auth_modes) or "未发现显式认证环境变量",
        ),
        Observation(
            key="client.settings",
            label="Claude Code 配置",
            value={
                "settings_present": info.settings_present,
                "settings_keys": info.settings_keys,
                "config_present": info.config_present,
                "config_size": info.config_size,
            },
            status=Status.info,
            source=source,
            visibility=Visibility.local,
            detail=(
                f"settings.json 键：{', '.join(info.settings_keys[:8])}"
                if info.settings_keys
                else "未发现 settings.json 覆盖"
            ),
        ),
    ]
    return info, observations
