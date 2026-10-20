"""Open the local dashboard, preferring an app-style Chromium window.

A browser tab works everywhere. On macOS a Chrome/Edge app window is much
cleaner for screen recording (no tab strip, no address bar), so we use one when
it is available and fall back to the default browser otherwise.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import webbrowser
from pathlib import Path

MAC_APP_CANDIDATES = (
    ("Google Chrome", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
    ("Google Chrome", "~/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
    ("Microsoft Edge", "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"),
    ("Brave Browser", "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"),
    ("Chromium", "/Applications/Chromium.app/Contents/MacOS/Chromium"),
    ("Arc", "/Applications/Arc.app/Contents/MacOS/Arc"),
)

PROFILE_DIR_NAME = "window-profile"


def find_app_browser() -> Path | None:
    if sys.platform != "darwin":
        return None
    for _name, raw in MAC_APP_CANDIDATES:
        path = Path(os.path.expanduser(raw))
        if path.exists():
            return path
    return None


def launch(
    url: str,
    *,
    app_window: bool = True,
    width: int = 1440,
    height: int = 940,
    profile_dir: Path | None = None,
) -> str:
    """Open ``url`` and report which surface was used: app / tab / manual."""
    if app_window:
        browser = find_app_browser()
        if browser is not None:
            argv = [
                str(browser),
                f"--app={url}",
                f"--window-size={width},{height}",
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-features=Translate",
            ]
            if profile_dir is not None:
                profile_dir.mkdir(parents=True, exist_ok=True)
                argv.append(f"--user-data-dir={profile_dir}")
            try:
                subprocess.Popen(  # noqa: S603 - fixed binary, local URL only
                    argv,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
                return "app"
            except OSError:
                pass
    try:
        if webbrowser.open(url):
            return "tab"
    except Exception:  # noqa: BLE001 - opening a browser is best-effort
        pass
    return "manual"


def can_launch_app() -> bool:
    return find_app_browser() is not None


def which(command: str) -> str | None:
    return shutil.which(command)
