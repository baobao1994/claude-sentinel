"""Optional deep behavior checks. Aggregate counts only; timestamps, never content."""

from __future__ import annotations

import json
import re
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


def _cron_jobs() -> int:
    count = 0
    try:
        proc = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=5)
        if proc.returncode == 0:
            count += sum(1 for line in proc.stdout.splitlines() if "claude" in line.lower())
    except (OSError, subprocess.SubprocessError):
        pass
    launch_dir = Path.home() / "Library" / "LaunchAgents"
    if launch_dir.exists():
        for plist in launch_dir.glob("*.plist"):
            try:
                text = plist.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if "claude" in text.lower():
                count += 1
    return count


def _shell_batch_hits() -> int:
    hits = 0
    patterns = re.compile(r"\b(for|xargs|while)\b", re.I)
    for name in (".zsh_history", ".bash_history"):
        path = Path.home() / name
        if not path.exists():
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for line in lines[-5000:]:
            low = line.lower()
            if "claude" in low and patterns.search(line):
                hits += 1
    return hits


def _session_rate() -> float | None:
    """Max requests in any 60s window, using timestamps only (no content)."""
    root = Path.home() / ".claude" / "projects"
    if not root.exists():
        return None
    files = sorted(
        root.rglob("*.jsonl"),
        key=lambda p: p.stat().st_mtime if p.exists() else 0,
        reverse=True,
    )[:80]
    times: list[datetime] = []
    for path in files:
        try:
            with path.open("r", encoding="utf-8", errors="ignore") as handle:
                for line in handle:
                    if '"timestamp"' not in line:
                        continue
                    try:
                        item = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    raw = item.get("timestamp") if isinstance(item, dict) else None
                    if not isinstance(raw, str):
                        continue
                    try:
                        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
                    except ValueError:
                        continue
                    if parsed.tzinfo is None:
                        parsed = parsed.replace(tzinfo=timezone.utc)
                    times.append(parsed)
        except OSError:
            continue
    if len(times) < 2:
        return None
    times.sort()
    best = 0
    left = 0
    for right, current in enumerate(times):
        while current - times[left] > timedelta(seconds=60):
            left += 1
        best = max(best, right - left + 1)
    return float(best)


def _session_files() -> dict[str, Any]:
    root = Path.home() / ".claude" / "projects"
    if not root.exists():
        return {"project_files": 0, "total_bytes": 0}
    files = list(root.rglob("*.jsonl"))
    total = 0
    for path in files[-500:]:
        try:
            total += path.stat().st_size
        except OSError:
            continue
    return {"project_files": len(files), "total_bytes": total}


def collect_behavior() -> dict[str, Any]:
    data: dict[str, Any] = {
        "cron_jobs": _cron_jobs(),
        "shell_batch_hits": _shell_batch_hits(),
        "session_rate_per_min": _session_rate(),
        "notes": [],
    }
    data.update(_session_files())
    if data["project_files"]:
        data["notes"].append(
            f"发现 {data['project_files']} 个 Claude Code 会话文件；deep 模式只读取时间戳和大小，不保存内容。"
        )
    return data
