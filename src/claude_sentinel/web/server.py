"""Local-only web dashboard.

The server binds to 127.0.0.1 by default, serves a three.js page, and exposes a
small JSON API. POST /api/scan requires a per-process token and a same-origin
request; no CORS headers are emitted.
"""

from __future__ import annotations

import json
import mimetypes
import secrets
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from claude_sentinel import __version__, launch
from claude_sentinel.config import Settings
from claude_sentinel.history import HistoryStore
from claude_sentinel.models import Report
from claude_sentinel.pipeline import run_scan
from claude_sentinel.progress import stage_public
from claude_sentinel.redact import redact_ips_in_obj

STATIC = Path(__file__).parent / "static"
PUBLIC_FILES = {
    "app.js",
    "styles.css",
    "three.module.min.js",
    "three-LICENSE.txt",
}
INDEX = STATIC / "index.html"


class _ClientGone(Exception):
    """Raised when the browser closed the event stream mid-scan."""


def _public(report: Report, settings: Settings) -> dict[str, Any]:
    data = report.model_dump(mode="json")
    if not settings.show_ip:
        data = redact_ips_in_obj(data)
    return data


def _history_rows(store: HistoryStore, limit: int = 10) -> list[dict[str, Any]]:
    keys = (
        "id",
        "started_at",
        "verdict",
        "score",
        "country",
        "ip_masked",
        "asn",
        "timezone",
        "account_state",
    )
    return [{key: row.get(key) for key in keys} for row in store.recent(limit)]


class _Handler(BaseHTTPRequestHandler):
    server_version = "ClaudeSentinelWeb/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, *args: object) -> None:  # keep the terminal clean
        return

    # ------------------------------------------------------------------ utils
    def _send(self, code: int, body: bytes, content_type: str, cache: str = "no-store") -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", cache)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, payload: Any) -> None:
        self._send(
            code,
            json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            "application/json; charset=utf-8",
        )

    def _error(self, code: int, message: str) -> None:
        self._json(code, {"error": message})

    def _sse_open(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.close_connection = True

    def _sse(self, event: str, payload: Any) -> None:
        body = f"event: {event}\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"
        try:
            self.wfile.write(body.encode("utf-8"))
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            raise _ClientGone from None

    def _origin_ok(self) -> bool:
        origin = self.headers.get("Origin")
        if not origin:
            return True
        allowed = getattr(self.server, "allowed_origins", set())
        return origin in allowed

    def _token_ok(self) -> bool:
        supplied = self.headers.get("X-Sentinel-Token", "")
        expected = getattr(self.server, "token", "")
        return bool(supplied and expected and secrets.compare_digest(supplied, expected))

    def _settings(self) -> Settings:
        return self.server.app_settings  # type: ignore[no-any-return]

    def _store(self) -> HistoryStore:
        return HistoryStore(self._settings().db_path)

    # -------------------------------------------------------------------- GET
    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path

        if path in {"/", "/index.html"}:
            try:
                html = INDEX.read_text(encoding="utf-8")
            except OSError:
                self._error(500, "dashboard assets missing")
                return
            html = html.replace("__TOKEN__", getattr(self.server, "token", ""))
            html = html.replace("__VERSION__", __version__)
            self._send(200, html.encode("utf-8"), "text/html; charset=utf-8")
            return

        if path.startswith("/static/"):
            name = path[len("/static/") :]
            if name not in PUBLIC_FILES:
                self._error(404, "not found")
                return
            file_path = STATIC / name
            try:
                body = file_path.read_bytes()
            except OSError:
                self._error(404, "not found")
                return
            content_type = mimetypes.guess_type(name)[0] or "application/octet-stream"
            if content_type.startswith("text/") or content_type in {"application/javascript", "text/javascript"}:
                content_type += "; charset=utf-8"
            self._send(200, body, content_type, cache="public, max-age=3600")
            return

        if path == "/api/health":
            self._json(200, {"ok": True, "version": __version__})
            return

        if path == "/api/meta":
            store = self._store()
            last = store.last()
            account_state = last.get("account_state") if last else None
            self._json(
                200,
                {
                    "version": __version__,
                    "has_report": bool(last),
                    "reference_mode": account_state in {None, "unknown", ""},
                    "account_state": account_state or "unknown",
                    "stages": stage_public(),
                    "app_window": bool(getattr(self.server, "app_window", False)),
                    "autostart": bool(getattr(self.server, "autostart", False)),
                },
            )
            return

        if path == "/api/latest":
            store = self._store()
            last = store.last()
            if not last or not last.get("report_json"):
                self._error(404, "no report")
                return
            try:
                report = Report.model_validate_json(last["report_json"])
            except Exception:
                self._error(500, "report unreadable")
                return
            self._json(200, _public(report, self._settings()))
            return

        if path == "/api/history":
            limit_raw = parse_qs(parsed.query).get("limit", ["10"])[0]
            try:
                limit = max(1, min(50, int(limit_raw)))
            except ValueError:
                limit = 10
            self._json(200, {"rows": _history_rows(self._store(), limit)})
            return

        self._error(404, "not found")

    # ------------------------------------------------------------------- POST
    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        if path not in {"/api/scan", "/api/scan/stream"}:
            self._error(404, "not found")
            return
        if not self._origin_ok():
            self._error(403, "bad origin")
            return
        if not self._token_ok():
            self._error(403, "bad token")
            return
        lock: threading.Lock = self.server.scan_lock
        if not lock.acquire(blocking=False):
            self._error(409, "scan already running")
            return
        try:
            if path == "/api/scan/stream":
                self._scan_stream()
            else:
                settings = self._settings()
                report = run_scan(settings, store=self._store())
                self._json(200, _public(report, settings))
        except _ClientGone:
            return
        except RuntimeError as exc:
            self._safe_error(500, str(exc))
        except Exception:
            self._safe_error(500, "scan failed")
        finally:
            lock.release()

    def _safe_error(self, code: int, message: str) -> None:
        try:
            self._error(code, message)
        except (BrokenPipeError, ConnectionResetError):
            return

    def _scan_stream(self) -> None:
        """Server-sent events: one per stage transition, then the full report."""
        settings = self._settings()
        store = self._store()
        started = time.monotonic()

        self._sse_open()
        self._sse("open", {"total": len(stage_public()), "version": __version__})

        def progress(stage_id: str, phase: str, detail: str | None, elapsed_ms: int | None) -> None:
            self._sse(
                "stage",
                {
                    "id": stage_id,
                    "phase": phase,
                    "detail": detail,
                    "elapsed_ms": elapsed_ms,
                    "at_ms": int((time.monotonic() - started) * 1000),
                },
            )

        try:
            report = run_scan(settings, store=store, progress=progress)
        except RuntimeError as exc:
            self._sse("failed", {"error": str(exc)})
            return
        except Exception:  # noqa: BLE001 - report a clean failure to the UI
            self._sse("failed", {"error": "scan failed"})
            return

        self._sse(
            "report",
            {
                "report": _public(report, settings),
                "history": _history_rows(store, 10),
                "duration_ms": int((time.monotonic() - started) * 1000),
            },
        )
        self._sse("done", {"run_id": report.run_id})


def build_server(
    settings: Settings,
    host: str = "127.0.0.1",
    port: int = 8765,
    app_window: bool = False,
    autostart: bool = False,
) -> ThreadingHTTPServer:
    """Create (but do not start) the dashboard server. Tests use this too."""
    settings.ensure()
    server = ThreadingHTTPServer((host, port), _Handler)
    server.daemon_threads = True
    server.app_settings = settings  # type: ignore[attr-defined]
    server.token = secrets.token_urlsafe(24)  # type: ignore[attr-defined]
    server.scan_lock = threading.Lock()  # type: ignore[attr-defined]
    server.autostart = bool(autostart)  # type: ignore[attr-defined]
    server.app_window = bool(app_window)  # type: ignore[attr-defined]
    actual_port = server.server_address[1]
    display_host = "127.0.0.1" if host in {"0.0.0.0", "::"} else host
    server.allowed_origins = {  # type: ignore[attr-defined]
        f"http://{display_host}:{actual_port}",
        f"http://localhost:{actual_port}",
    }
    server.display_url = f"http://{display_host}:{actual_port}/"  # type: ignore[attr-defined]
    return server


def run_web(
    settings: Settings,
    host: str = "127.0.0.1",
    port: int = 8765,
    open_browser: bool = True,
    app_window: bool = False,
    autostart: bool = False,
    width: int = 1440,
    height: int = 940,
) -> None:
    prefer_app = app_window and launch.can_launch_app()
    server = build_server(
        settings,
        host=host,
        port=port,
        app_window=prefer_app,
        autostart=autostart,
    )
    url = server.display_url  # type: ignore[attr-defined]
    if not open_browser:
        served = "no window"
    elif prefer_app:
        served = "app window"
    else:
        served = "browser tab"
    print(f"Claude Sentinel Web: {url}  ({served})", file=sys.stderr)
    if host in {"0.0.0.0", "::"}:
        print("警告：正在监听所有网卡；建议只用 127.0.0.1。", file=sys.stderr)
    if open_browser:
        surface = launch.launch(
            url,
            app_window=prefer_app,
            width=width,
            height=height,
            profile_dir=settings.home / launch.PROFILE_DIR_NAME if prefer_app else None,
        )
        if surface == "manual":
            print("无法自动打开浏览器，请手动访问上面的地址。", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止。", file=sys.stderr)
    finally:
        server.server_close()
