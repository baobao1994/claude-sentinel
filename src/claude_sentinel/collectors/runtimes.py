"""What each *runtime* actually egresses from.

A browser and a terminal do not necessarily take the same path:

* Browsers and macOS/curl honour the system proxy.
* Node.js (the runtime Claude Code runs on) does **not** read the macOS system
  proxy; it only honours ``HTTPS_PROXY``-style env vars. With those unset it
  connects directly, so Claude Code can leave through a completely different
  IP than the browser on the same machine.

Each probe is a single GET to ``claude.ai/cdn-cgi/trace`` from that runtime, so
the answer is literally "what Claude sees from here". Read-only, no payload.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from typing import Any

from claude_sentinel.models import (
    Confidence,
    Observation,
    RuntimeProbe,
    Source,
    SourceKind,
    Status,
)

TRACE_URL = "https://claude.ai/cdn-cgi/trace"
CACHE_TTL = 300

# Node script kept tiny and self-contained: no deps, hard timeout, prints JSON.
NODE_SCRIPT = r"""
const https = require('https');
const url = process.argv[2];
const done = (obj) => { process.stdout.write(JSON.stringify(obj)); };
// family:4 avoids Node's Happy-Eyeballs path, which surfaces as an opaque
// AggregateError / ECONNREFUSED on machines without a working IPv6 route.
const req = https.get(url, { timeout: 8000, family: 4 }, (res) => {
  let body = '';
  res.on('data', (c) => (body += c));
  res.on('end', () => {
    const out = {};
    for (const line of body.split('\n')) {
      const i = line.indexOf('=');
      if (i > 0) out[line.slice(0, i)] = line.slice(i + 1);
    }
    done({ ok: true, ip: out.ip || null, loc: out.loc || null, colo: out.colo || null });
  });
});
req.on('timeout', () => { req.destroy(); done({ ok: false, error: 'timeout' }); });
req.on('error', (e) => {
  const detail = e && e.errors ? e.errors.map((x) => x.code || x.message).join(',') : e.message || String(e);
  done({ ok: false, error: String(detail) });
});
"""

SOURCE = Source(
    name="claude.ai /cdn-cgi/trace (per runtime)",
    kind=SourceKind.edge,
    url=TRACE_URL,
    confidence=Confidence.high,
)


def _env_without_proxy() -> dict[str, str]:
    env = os.environ.copy()
    for key in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "NODE_OPTIONS",
    ):
        env.pop(key, None)
    return env


def _parse(data: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in data.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            out[key.strip()] = value.strip()
    return out


def probe_node(timeout: float = 12.0) -> RuntimeProbe:
    """The path Claude Code takes: Node, without proxy env vars."""
    node = shutil.which("node")
    if not node:
        return RuntimeProbe(
            runtime="node",
            label="Node / Claude Code",
            available=False,
            error="未安装 node",
        )
    # A real .cjs file, not `-e`: Node treats inline code differently and a
    # project package.json with "type": "module" breaks `require` under -e.
    with tempfile.NamedTemporaryFile("w", suffix=".cjs", delete=False, encoding="utf-8") as handle:
        handle.write(NODE_SCRIPT)
        script_path = handle.name
    try:
        proc = subprocess.run(
            [node, script_path, TRACE_URL],
            capture_output=True,
            text=True,
            timeout=timeout,
            env=_env_without_proxy(),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return RuntimeProbe(
            runtime="node",
            label="Node / Claude Code",
            available=True,
            error=str(exc)[:160],
        )
    finally:
        try:
            os.unlink(script_path)
        except OSError:
            pass
    if proc.returncode != 0 or not proc.stdout.strip():
        return RuntimeProbe(
            runtime="node",
            label="Node / Claude Code",
            available=True,
            error=(proc.stderr or "no output").strip()[:160],
        )
    try:
        payload: dict[str, Any] = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return RuntimeProbe(runtime="node", label="Node / Claude Code", available=True, error="坏输出")
    return RuntimeProbe(
        runtime="node",
        label="Node / Claude Code",
        available=True,
        ok=bool(payload.get("ok")),
        ip=payload.get("ip"),
        loc=payload.get("loc"),
        colo=payload.get("colo"),
        error=payload.get("error"),
        proxies_env=False,
    )


def probe_shell(timeout: float = 10.0) -> RuntimeProbe:
    """The shell path: curl is used because it is what scripts and hooks use."""
    curl = shutil.which("curl")
    if not curl:
        return RuntimeProbe(runtime="shell", label="Shell / curl", available=False, error="未安装 curl")
    try:
        proc = subprocess.run(
            [curl, "-sS", "--max-time", "8", TRACE_URL],
            capture_output=True,
            text=True,
            timeout=timeout,
            env=_env_without_proxy(),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return RuntimeProbe(runtime="shell", label="Shell / curl", available=True, error=str(exc)[:160])
    if proc.returncode != 0 or not proc.stdout:
        return RuntimeProbe(
            runtime="shell",
            label="Shell / curl",
            available=True,
            error=(proc.stderr or "no output").strip()[:160],
        )
    trace = _parse(proc.stdout)
    return RuntimeProbe(
        runtime="shell",
        label="Shell / curl",
        available=True,
        ok=bool(trace.get("ip")),
        ip=trace.get("ip"),
        loc=trace.get("loc"),
        colo=trace.get("colo"),
        proxies_env=False,
    )


def collect_runtimes() -> tuple[list[RuntimeProbe], list[Observation]]:
    probes = [probe_node(), probe_shell()]
    observations: list[Observation] = []
    for probe in probes:
        if not probe.available:
            status = Status.skipped
            detail = probe.error or "不可用"
        elif not probe.ok:
            status = Status.unknown
            detail = probe.error or "探测失败"
        else:
            status = Status.ok
            detail = f"{probe.ip} · {probe.loc} · colo={probe.colo}"
        observations.append(
            Observation(
                key=f"runtime.{probe.runtime}",
                label=probe.label,
                value={
                    "ip": probe.ip,
                    "loc": probe.loc,
                    "colo": probe.colo,
                    "proxies_env": probe.proxies_env,
                },
                status=status,
                source=SOURCE,
                visibility="server",
                detail=detail,
                error=probe.error,
            )
        )
    return probes, observations
