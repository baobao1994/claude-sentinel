"""Runtime settings, paths and rule weights."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from importlib.resources import files
from pathlib import Path
from typing import Any

import yaml

APP_DIR_NAME = ".claude-sentinel"


def default_home() -> Path:
    override = os.environ.get("CLAUDE_SENTINEL_HOME")
    if override:
        return Path(override).expanduser()
    return Path.home() / APP_DIR_NAME


@dataclass
class Settings:
    home: Path = field(default_factory=default_home)
    proxy: str | None = None
    timeout: float = 8.0
    ip_intel: bool = True
    show_ip: bool = False
    no_anim: bool = False
    compact: bool = False
    deep: bool = False
    explain: bool = False
    offline: bool = False
    html: bool = True
    open_report: bool = True
    json_stdout: bool = False
    json_out: Path | None = None
    account_token: str | None = None
    account_cookie: str | None = None
    account_ua: str | None = None
    account_method: str = "none"

    @property
    def cache_dir(self) -> Path:
        return self.home / "cache"

    @property
    def reports_dir(self) -> Path:
        return self.home / "reports"

    @property
    def db_path(self) -> Path:
        return self.home / "sentinel.db"

    @property
    def profile_path(self) -> Path:
        return self.home / "profile.json"

    def ensure(self) -> None:
        for path in (self.home, self.cache_dir, self.reports_dir):
            path.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(path, 0o700)
            except OSError:
                pass


def load_weights() -> dict[str, Any]:
    path = files("claude_sentinel.data").joinpath("weights.yaml")
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def package_data_text(name: str) -> str:
    return files("claude_sentinel.data").joinpath(name).read_text(encoding="utf-8")
