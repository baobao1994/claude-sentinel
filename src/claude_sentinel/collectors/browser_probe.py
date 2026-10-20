"""Optional local browser probe: WebRTC, canvas, fonts and browser egress.

The page is served from 127.0.0.1 and posts back to 127.0.0.1 only. It makes
two external requests that are inherent to the measurement: Cloudflare's trace
endpoint (to learn the browser's egress IP) and public STUN servers (WebRTC).
"""

from __future__ import annotations

import json
import re
import secrets
import sys
import threading
import webbrowser
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from claude_sentinel.collectors.base import cache_write
from claude_sentinel.config import Settings
from claude_sentinel.models import BrowserProbe, WebRtcCandidate

MAX_BODY = 1_000_000


def _parse_candidates(values: list[str]) -> list[WebRtcCandidate]:
    result: list[WebRtcCandidate] = []
    for raw in values:
        if not isinstance(raw, str) or not raw:
            continue
        ip = None
        kind = None
        match = re.search(r"\btyp\s+(\w+)", raw)
        if match:
            kind = match.group(1)
        # candidate:... <ip> <port> typ ...
        m = re.search(r"candidate:\S+\s+\d+\s+\w+\s+\d+\s+([0-9a-fA-F:.]+)\s+\d+\s+typ", raw)
        if m:
            ip = m.group(1)
        if ip and (ip.endswith(".local") or ip.startswith("0.")):
            ip = None
        result.append(WebRtcCandidate(candidate=raw, ip=ip, kind=kind))
    return result


def _build_probe(payload: dict[str, Any]) -> BrowserProbe:
    return BrowserProbe(
        collected_at=datetime.now(timezone.utc),
        timezone=payload.get("timezone"),
        utc_offset_minutes=payload.get("utc_offset_minutes"),
        locale=payload.get("locale"),
        languages=payload.get("languages") or [],
        user_agent=payload.get("user_agent"),
        platform=payload.get("platform"),
        ua_mobile=payload.get("ua_mobile"),
        screen=payload.get("screen"),
        device_pixel_ratio=payload.get("device_pixel_ratio"),
        hardware_concurrency=payload.get("hardware_concurrency"),
        device_memory=payload.get("device_memory"),
        canvas_hash=payload.get("canvas_hash"),
        webgl_vendor=payload.get("webgl_vendor"),
        webgl_renderer=payload.get("webgl_renderer"),
        webgl_hash=payload.get("webgl_hash"),
        fonts=payload.get("fonts") or [],
        webrtc=_parse_candidates(payload.get("webrtc") or []),
        egress_ip=payload.get("egress_ip"),
        egress_country=payload.get("egress_country"),
        egress_colo=payload.get("egress_colo"),
        warp=payload.get("warp"),
        dnt=payload.get("dnt"),
        cookies_enabled=payload.get("cookies_enabled"),
        connection_type=payload.get("connection_type"),
    )


PAGE = """<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark">
<meta name="referrer" content="no-referrer">
<title>Claude Sentinel · Browser Probe</title>
<style>
  :root{--bg:#05070b;--panel:#0b1018;--line:#12202e;--text:#e5f2ff;--muted:#6b8299;--cyan:#22d3ee;--green:#34d399;--red:#f43f5e}
  *{box-sizing:border-box}body{margin:0;background:radial-gradient(800px 400px at 70% -10%,rgba(34,211,238,.12),transparent 60%),var(--bg);color:var(--text);font-family:system-ui,-apple-system,"PingFang SC",sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
  .card{width:min(680px,100%);border:1px solid var(--line);background:linear-gradient(180deg,rgba(11,16,24,.96),rgba(7,10,15,.96));border-radius:16px;padding:28px;box-shadow:0 30px 90px rgba(0,0,0,.5)}
  .brand{font-family:ui-monospace,Menlo,monospace;letter-spacing:.14em;font-size:12px;color:var(--cyan)}
  h1{font-size:26px;margin:12px 0 8px}p{color:#aec4d8;margin:0 0 12px;font-size:14px}
  .row{display:flex;justify-content:space-between;gap:12px;border-top:1px solid var(--line);padding:9px 0;font-size:13px}
  .row:first-of-type{border-top:0}.k{color:var(--muted)}.v{font-family:ui-monospace,Menlo,monospace;color:var(--text);text-align:right;max-width:70%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .status{margin-top:16px;padding:10px 12px;border:1px solid var(--line);border-radius:8px;font-family:ui-monospace,Menlo,monospace;font-size:12px;color:var(--muted)}
  .ok{color:var(--green)}.err{color:var(--red)}
  .note{font-size:11px;color:var(--muted);line-height:1.7;margin-top:14px}
</style></head>
<body><div class="card">
  <div class="brand">◈ CLAUDE SENTINEL / BROWSER PROBE</div>
  <h1>浏览器环境采集</h1>
  <p>这一页只把数据发回 <code>127.0.0.1</code>。请保持页面打开约 5 秒。</p>
  <div id="rows"></div>
  <div class="status" id="status">准备中…</div>
  <div class="note">
    外部请求仅用于测量：Cloudflare trace（获取浏览器出口 IP）、公共 STUN（WebRTC 候选）。
    不会读取 Cookie、历史记录或账号内容。
  </div>
</div>
<script>
const TOKEN = "__TOKEN__";
const rows = document.getElementById('rows');
const statusEl = document.getElementById('status');
const out = {
  timezone: null, utc_offset_minutes: null, locale: null, languages: [],
  user_agent: navigator.userAgent, platform: navigator.platform,
  ua_mobile: null, screen: null, device_pixel_ratio: window.devicePixelRatio || 1,
  hardware_concurrency: navigator.hardwareConcurrency || null,
  device_memory: navigator.deviceMemory || null,
  canvas_hash: null, webgl_vendor: null, webgl_renderer: null, webgl_hash: null,
  fonts: [], webrtc: [], egress_ip: null, egress_country: null, egress_colo: null,
  warp: null, dnt: navigator.doNotTrack || null,
  cookies_enabled: navigator.cookieEnabled,
  connection_type: (navigator.connection && navigator.connection.effectiveType) || null
};
function add(k, v) {
  if (v === null || v === undefined || v === '') return;
  const row = document.createElement('div'); row.className = 'row';
  const a = document.createElement('span'); a.className = 'k'; a.textContent = k;
  const b = document.createElement('span'); b.className = 'v'; b.textContent = String(v);
  row.appendChild(a); row.appendChild(b); rows.appendChild(row);
}
async function hashText(text) {
  try {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
    return Array.from(new Uint8Array(buf)).map(x => x.toString(16).padStart(2, '0')).join('');
  } catch (e) {
    let h = 2166136261;
    for (let i = 0; i < text.length; i++) { h ^= text.charCodeAt(i); h = Math.imul(h, 16777619); }
    return (h >>> 0).toString(16);
  }
}
function collectBasics() {
  out.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone || null;
  out.utc_offset_minutes = -new Date().getTimezoneOffset();
  out.locale = Intl.DateTimeFormat().resolvedOptions().locale || null;
  out.languages = Array.from(navigator.languages || []);
  out.screen = `${screen.width}x${screen.height}@${window.devicePixelRatio || 1}`;
  if (navigator.userAgentData) out.ua_mobile = navigator.userAgentData.mobile;
  else out.ua_mobile = /Mobi|Android/i.test(navigator.userAgent);
}
function collectCanvas() {
  const c = document.createElement('canvas'); c.width = 260; c.height = 70;
  const ctx = c.getContext('2d');
  ctx.textBaseline = 'top';
  ctx.font = '16px "Arial"';
  ctx.fillStyle = '#f60'; ctx.fillRect(0, 0, 80, 20);
  ctx.fillStyle = '#069'; ctx.fillText('Claude Sentinel 探针', 4, 24);
  ctx.strokeStyle = 'rgba(102,204,0,.7)'; ctx.arc(200, 35, 20, 0, Math.PI * 2); ctx.stroke();
  return { data: c.toDataURL(), hashSource: 'canvas' };
}
function collectWebGL() {
  const c = document.createElement('canvas');
  const gl = c.getContext('webgl') || c.getContext('experimental-webgl');
  if (!gl) return;
  const dbg = gl.getExtension('WEBGL_debug_renderer_info');
  if (dbg) {
    out.webgl_vendor = gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL);
    out.webgl_renderer = gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL);
  }
  const attrs = gl.getParameter(gl.VERSION) + '|' + gl.getParameter(gl.SHADING_LANGUAGE_VERSION);
  return attrs;
}
function collectFonts() {
  const baseFonts = ['monospace', 'sans-serif', 'serif'];
  const testFonts = ['PingFang SC','Heiti SC','Songti SC','Kaiti SC','Microsoft YaHei','SimSun',
    'Noto Sans CJK SC','Source Han Sans SC','Arial Unicode MS','Segoe UI','Helvetica Neue'];
  const canvas = document.createElement('canvas');
  const ctx = canvas.getContext('2d');
  const text = 'mmmmmmmmmmlli';
  const baseWidth = {};
  for (const base of baseFonts) {
    ctx.font = `72px ${base}`;
    baseWidth[base] = ctx.measureText(text).width;
  }
  const found = [];
  for (const font of testFonts) {
    for (const base of baseFonts) {
      ctx.font = `72px "${font}", ${base}`;
      if (ctx.measureText(text).width !== baseWidth[base]) { found.push(font); break; }
    }
  }
  return found;
}
function collectWebRTC() {
  return new Promise(resolve => {
    const found = [];
    let pc;
    try {
      pc = new RTCPeerConnection({ iceServers: [
        { urls: 'stun:stun.l.google.com:19302' },
        { urls: 'stun:stun.cloudflare.com:3478' }
      ]});
    } catch (e) { resolve(found); return; }
    const done = () => { try { pc.close(); } catch (e) {} resolve(found); };
    const timer = setTimeout(done, 4200);
    pc.onicecandidate = e => {
      if (e.candidate && e.candidate.candidate) found.push(e.candidate.candidate);
    };
    try {
      pc.createDataChannel('probe');
      pc.createOffer().then(offer => pc.setLocalDescription(offer)).catch(done);
    } catch (e) { done(); }
  });
}
async function collectEgress() {
  try {
    const res = await fetch('https://www.cloudflare.com/cdn-cgi/trace', { cache: 'no-store' });
    const text = await res.text();
    const map = {};
    text.split('\\n').forEach(line => { const i = line.indexOf('='); if (i > 0) map[line.slice(0, i)] = line.slice(i + 1); });
    out.egress_ip = map.ip || null;
    out.egress_country = map.loc || null;
    out.egress_colo = map.colo || null;
    out.warp = map.warp || null;
  } catch (e) {}
  if (!out.egress_ip) {
    try {
      const res = await fetch('https://api.ipapi.is/', { cache: 'no-store' });
      const data = await res.json();
      out.egress_ip = data.ip || null;
      out.egress_country = data.country_code || data.country || null;
    } catch (e) {}
  }
}
(async function () {
  collectBasics();
  const canvas = collectCanvas();
  out.canvas_hash = await hashText(canvas.data);
  const gl = collectWebGL();
  out.webgl_hash = gl ? await hashText(gl) : null;
  out.fonts = collectFonts();
  await collectEgress();
  out.webrtc = await collectWebRTC();
  add('浏览器出口', out.egress_ip);
  add('出口地区', out.egress_country);
  add('时区', out.timezone);
  add('语言', out.languages.join(', '));
  add('WebRTC 候选', out.webrtc.length);
  add('Canvas 指纹', out.canvas_hash ? out.canvas_hash.slice(0, 16) + '…' : '—');
  add('字体', out.fonts.join(', '));
  statusEl.textContent = '提交到本地…';
  try {
    const res = await fetch('/api/probe?token=' + encodeURIComponent(TOKEN), {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(out)
    });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    statusEl.className = 'status ok';
    statusEl.textContent = '已提交到 127.0.0.1。可以关闭此页，回到终端继续。';
  } catch (e) {
    statusEl.className = 'status err';
    statusEl.textContent = '提交失败：' + e.message + '（请确认终端仍在运行）';
  }
})();
</script>
</body></html>
"""


class _Handler(BaseHTTPRequestHandler):
    server_version = "ClaudeSentinelProbe/1.0"

    def log_message(self, *args: object) -> None:  # silence
        return

    def _send(self, code: int, body: bytes, content_type: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path in {"/", "/probe"}:
            token = getattr(self.server, "probe_token", "")
            supplied = parse_qs(parsed.query).get("token", [""])[0]
            if not supplied or not secrets.compare_digest(supplied, token):
                self._send(403, b"forbidden", "text/plain")
                return
            html = PAGE.replace("__TOKEN__", token).encode("utf-8")
            self._send(200, html, "text/html; charset=utf-8")
            return
        if parsed.path == "/health":
            self._send(200, b'{"ok":true}', "application/json")
            return
        self._send(404, b"not found", "text/plain")

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path != "/api/probe":
            self._send(404, b"not found", "text/plain")
            return
        token = parse_qs(parsed.query).get("token", [""])[0]
        expected = getattr(self.server, "probe_token", "")
        if not token or not secrets.compare_digest(token, expected):
            self._send(403, b"forbidden", "text/plain")
            return
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length <= 0 or length > MAX_BODY:
            self._send(413, b"too large", "text/plain")
            return
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send(400, b"bad json", "text/plain")
            return
        if not isinstance(payload, dict):
            self._send(400, b"bad payload", "text/plain")
            return
        self.server.probe_payload = payload  # type: ignore[attr-defined]
        self.server.probe_event.set()  # type: ignore[attr-defined]
        self._send(204, b"", "application/json")


def run_browser_probe(
    settings: Settings,
    timeout: float = 150.0,
    open_browser: bool = True,
    on_url: Any = None,
) -> BrowserProbe | None:
    token = secrets.token_urlsafe(18)
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.daemon_threads = True
    server.probe_token = token  # type: ignore[attr-defined]
    server.probe_payload = None  # type: ignore[attr-defined]
    server.probe_event = threading.Event()  # type: ignore[attr-defined]
    port = server.server_address[1]
    url = f"http://127.0.0.1:{port}/?token={token}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        if on_url is not None:
            try:
                on_url(url)
            except Exception:
                pass
        if open_browser:
            try:
                webbrowser.open(url)
            except Exception:
                pass
        print(f"浏览器探针：{url}", file=sys.stderr)
        print("如果浏览器没有自动打开，请手动粘贴上面的地址。", file=sys.stderr)
        print("保持在页面约 5 秒；采集完成后会自动返回。", file=sys.stderr)
        got = server.probe_event.wait(timeout)  # type: ignore[attr-defined]
        payload = server.probe_payload if got else None  # type: ignore[attr-defined]
        if not isinstance(payload, dict):
            print("未收到浏览器数据（超时或页面被关闭）。", file=sys.stderr)
            return None
        probe = _build_probe(payload)
        cache_write(settings.cache_dir, "browser_probe", probe.model_dump(mode="json"))
        return probe
    finally:
        server.shutdown()
        server.server_close()
