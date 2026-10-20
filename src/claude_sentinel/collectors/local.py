"""Local environment: timezone, locale, fonts, browsers, proxy, fingerprint."""

from __future__ import annotations

import hashlib
import json
import locale as locale_mod
import os
import platform
import re
import secrets
import subprocess
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from claude_sentinel.models import (
    Confidence,
    LocalInfo,
    Observation,
    Source,
    SourceKind,
    Status,
    Visibility,
)

CN_FONTS = {
    "PingFang SC": [
        "/System/Library/Fonts/PingFang.ttc",
        "/System/Library/Fonts/PingFangUI.ttc",
    ],
    "Heiti SC": ["/System/Library/Fonts/STHeiti Light.ttc"],
    "Songti SC": ["/System/Library/Fonts/Supplemental/Songti.ttc"],
    "Arial Unicode": ["/Library/Fonts/Arial Unicode.ttf"],
    "Noto Sans CJK": [
        "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
        "/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc",
    ],
    "WenQuanYi": ["/usr/share/fonts/truetype/wqy/wqy-microhei.ttc"],
}

BROWSERS = {
    "Safari": ["/Applications/Safari.app"],
    "Google Chrome": ["/Applications/Google Chrome.app", "~/Applications/Google Chrome.app"],
    "Microsoft Edge": ["/Applications/Microsoft Edge.app"],
    "Firefox": ["/Applications/Firefox.app"],
    "Arc": ["/Applications/Arc.app"],
    "Brave": ["/Applications/Brave Browser.app"],
    "Opera": ["/Applications/Opera.app"],
    "360 浏览器": ["/Applications/360Browser.app", "/Applications/360极速浏览器.app"],
    "QQ 浏览器": ["/Applications/QQBrowser.app"],
    "搜狗浏览器": ["/Applications/SogouExplorer.app"],
    "UC 浏览器": ["/Applications/UCBrowser.app"],
    "夸克": ["/Applications/Quark.app"],
    "百度浏览器": ["/Applications/BaiduBrowser.app"],
    "猎豹浏览器": ["/Applications/LieBao.app"],
    "Maxthon": ["/Applications/Maxthon.app"],
}


def _readlink_timezone() -> str | None:
    try:
        target = os.readlink("/etc/localtime")
        marker = "zoneinfo/"
        if marker in target:
            return target.split(marker, 1)[1]
    except OSError:
        pass
    tz = os.environ.get("TZ")
    if tz:
        return tz
    try:
        name = datetime_timezone_name()
        if name:
            return name
    except Exception:
        pass
    return None


def datetime_timezone_name() -> str | None:
    from datetime import datetime

    tz = datetime.now().astimezone().tzinfo
    return getattr(tz, "key", None) or getattr(tz, "zone", None)


def _utc_offset() -> str | None:
    from datetime import datetime

    return datetime.now().astimezone().strftime("%z")


def _macos_preferences() -> tuple[str | None, list[str]]:
    """A terminal started with LANG=C still sits on a localised macOS UI."""
    if platform.system() != "Darwin":
        return None, []
    value = None
    languages: list[str] = []
    try:
        proc = subprocess.run(
            ["defaults", "read", "-g", "AppleLocale"],
            capture_output=True,
            text=True,
            timeout=4,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            value = proc.stdout.strip().replace("_", "-")
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        proc = subprocess.run(
            ["defaults", "read", "-g", "AppleLanguages"],
            capture_output=True,
            text=True,
            timeout=4,
        )
        if proc.returncode == 0:
            languages = re.findall(r'"([^"]+)"', proc.stdout)
    except (OSError, subprocess.SubprocessError):
        pass
    return value, languages


def _locale() -> tuple[str | None, list[str]]:
    raw = os.environ.get("LC_ALL") or os.environ.get("LANG") or os.environ.get("LC_CTYPE")
    value = None
    if raw:
        value = raw.split(".", 1)[0].replace("_", "-")
    if value and value.upper() in {"C", "POSIX"}:
        value = None
    if not value:
        try:
            lang, _enc = locale_mod.getlocale()
            if lang:
                value = lang.replace("_", "-")
        except Exception:
            pass
    mac_locale, mac_languages = _macos_preferences()
    if not value or value.upper() in {"C", "POSIX"}:
        value = mac_locale
    languages = []
    if value:
        languages.append(value)
    for item in mac_languages:
        item = item.replace("_", "-")
        if item and item not in languages:
            languages.append(item)
    extra = os.environ.get("LANGUAGE")
    if extra:
        for item in extra.split(":"):
            item = item.replace("_", "-")
            if item and item not in languages:
                languages.append(item)
    return value, languages


def _fonts() -> list[str]:
    found: list[str] = []
    for name, paths in CN_FONTS.items():
        for raw in paths:
            if Path(raw).expanduser().exists():
                found.append(name)
                break
    for directory in (Path.home() / "Library/Fonts", Path("/Library/Fonts")):
        if not directory.exists():
            continue
        try:
            for child in directory.iterdir():
                low = child.name.lower()
                if any(k in low for k in ("songti", "heiti", "kai", "fang", "yahei", "simsun", "cjk")):
                    name = child.stem
                    if name not in found:
                        found.append(name)
        except OSError:
            continue
    return sorted(set(found))[:12]


def _browsers() -> list[str]:
    found = []
    for name, paths in BROWSERS.items():
        for raw in paths:
            if Path(raw).expanduser().exists():
                found.append(name)
                break
    return found


def _mask_proxy_url(value: str) -> str:
    try:
        parts = urlsplit(value)
        if parts.password:
            netloc = parts.hostname or ""
            if parts.port:
                netloc += f":{parts.port}"
            parts = parts._replace(netloc=netloc)
        return urlunsplit(parts)
    except Exception:
        return "***"


def _proxy_env() -> dict[str, str]:
    found = {}
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy"):
        value = os.environ.get(key)
        if value:
            found[key] = _mask_proxy_url(value)
    return found


def _system_proxy() -> str | None:
    if platform.system() != "Darwin":
        return None
    try:
        proc = subprocess.run(
            ["scutil", "--proxy"], capture_output=True, text=True, timeout=4
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    enabled = []
    for line in lines:
        if line.startswith(("HTTPEnable", "HTTPSEnable", "SOCKSEnable", "ProxyAutoConfigEnable")):
            parts = line.split(":", 1)
            if len(parts) == 2 and parts[1].strip() == "1":
                enabled.append(parts[0])
    if not enabled:
        return "系统代理未启用"
    return "系统代理：" + ", ".join(enabled)


def _machine_fingerprint(home: Path | None = None) -> str:
    """Stable installation fingerprint.

    Network interfaces change (VPN/TUN), and IOPlatformUUID lookups can time
    out, so neither is a reliable per-run input. A persisted random install id
    gives a stable baseline while remaining local-only and non-identifying.
    """
    base = home or (Path.home() / ".claude-sentinel")
    token: str | None = None
    try:
        base.mkdir(parents=True, exist_ok=True)
        path = base / "device_id"
        if path.exists():
            token = path.read_text(encoding="utf-8").strip() or None
        if not token:
            token = secrets.token_hex(16)
            path.write_text(token + "\n", encoding="utf-8")
            try:
                path.chmod(0o600)
            except OSError:
                pass
    except OSError:
        token = None
    if not token:
        token = hashlib.sha256(
            f"{platform.node()}|{platform.machine()}|{platform.system()}".encode()
        ).hexdigest()
    digest = hashlib.sha256(f"{token}|{platform.machine()}".encode()).hexdigest()
    return digest[:16]


def collect_local(home: Path | None = None) -> tuple[LocalInfo, list[Observation]]:
    tz = _readlink_timezone()
    offset = _utc_offset()
    loc, languages = _locale()
    fonts = _fonts()
    browsers = _browsers()
    proxy_env = _proxy_env()
    system_proxy = _system_proxy()
    fingerprint = _machine_fingerprint(home)

    info = LocalInfo(
        os=f"{platform.system()} {platform.release()}",
        arch=platform.machine(),
        timezone=tz,
        utc_offset=offset,
        locale=loc,
        languages=languages,
        fonts_cn=fonts,
        browsers=browsers,
        default_browser=None,
        proxy_env=proxy_env,
        system_proxy=system_proxy,
        machine_fingerprint=fingerprint,
    )

    local_source = Source(
        name="Local OS",
        kind=SourceKind.local,
        confidence=Confidence.high,
    )
    observations = [
        Observation(
            key="local.timezone",
            label="系统时区",
            value={"timezone": tz, "utc_offset": offset},
            status=Status.info,
            source=local_source,
            visibility=Visibility.browser_js,
            detail=f"{tz or '?'} (UTC{offset or '?'})",
        ),
        Observation(
            key="local.locale",
            label="系统语言/区域",
            value={"locale": loc, "languages": languages},
            status=Status.info,
            source=local_source,
            visibility=Visibility.browser_js,
            detail=f"{loc or '?'} · {', '.join(languages) or '?'}",
        ),
        Observation(
            key="local.browsers",
            label="已安装浏览器",
            value=browsers,
            status=Status.info,
            source=local_source,
            visibility=Visibility.local,
            detail=", ".join(browsers) or "未发现常见浏览器",
        ),
        Observation(
            key="local.fonts",
            label="中文字体",
            value=fonts,
            status=Status.info,
            source=local_source,
            visibility=Visibility.local,
            detail=", ".join(fonts) or "未发现常见中文字体",
        ),
        Observation(
            key="local.proxy",
            label="代理配置",
            value={"env": proxy_env, "system": system_proxy},
            status=Status.info,
            source=local_source,
            visibility=Visibility.local,
            detail=system_proxy or (", ".join(proxy_env) if proxy_env else "未发现代理配置"),
        ),
        Observation(
            key="local.fingerprint",
            label="设备指纹（本地安装 ID）",
            value=fingerprint,
            status=Status.info,
            source=local_source,
            visibility=Visibility.local,
            detail=f"本地安装 ID 哈希 {fingerprint}（不上传）",
        ),
    ]
    return info, observations


def write_profile(path: Path, profile: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(profile, ensure_ascii=False, indent=2), encoding="utf-8")
