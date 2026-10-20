"""Command line interface: one scan, optional account probe, history and profile."""

from __future__ import annotations

import json
import os
import shutil
import sys
import webbrowser
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from claude_sentinel import __version__
from claude_sentinel.collectors.account import (
    probe_cookie,
    probe_oauth,
    read_claude_code_token,
)
from claude_sentinel.collectors.base import Http, cache_write
from claude_sentinel.collectors.browser_probe import run_browser_probe
from claude_sentinel.config import Settings, default_home, load_weights
from claude_sentinel.history import HistoryStore
from claude_sentinel.models import (
    AccountState,
    Profile,
    Report,
    VerdictCode,
)
from claude_sentinel.pipeline import load_profile, run_scan
from claude_sentinel.redact import mask_ip, redact_ips_in_obj, redact_text
from claude_sentinel.render.html import render_html
from claude_sentinel.render.hud_live import TerminalScanner
from claude_sentinel.render.terminal import render_report
from claude_sentinel.web.server import run_web

app = typer.Typer(
    add_completion=False,
    invoke_without_command=True,
    no_args_is_help=False,
    help="Local, read-only Claude environment self-check.",
)
console = Console(highlight=False)


def _settings(
    *,
    proxy: Optional[str] = None,
    show_ip: bool = False,
    no_ip_intel: bool = False,
    no_anim: bool = False,
    compact: bool = False,
    deep: bool = False,
    explain: bool = False,
    offline: bool = False,
    html: bool = True,
    open_report: bool = True,
    json_stdout: bool = False,
    json_out: Optional[Path] = None,
) -> Settings:
    settings = Settings(
        home=default_home(),
        proxy=proxy or os.environ.get("CLAUDE_SENTINEL_PROXY"),
        show_ip=show_ip,
        ip_intel=not no_ip_intel,
        no_anim=no_anim,
        compact=compact,
        deep=deep,
        explain=explain,
        offline=offline,
        html=html,
        open_report=open_report,
        json_stdout=json_stdout,
        json_out=json_out,
    )
    settings.account_token = os.environ.get("CLAUDE_SENTINEL_OAUTH_TOKEN")
    settings.account_cookie = os.environ.get("CLAUDE_SENTINEL_SESSION_KEY")
    settings.account_ua = os.environ.get("CLAUDE_SENTINEL_USER_AGENT")
    return settings


def _public_dict(report: Report, settings: Settings) -> dict:
    data = report.model_dump(mode="json")
    if not settings.show_ip:
        data = redact_ips_in_obj(data)
    return data


def _write_json(data: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass


def _exit_code(code: VerdictCode) -> int:
    if code == VerdictCode.ready:
        return 0
    if code == VerdictCode.caution:
        return 1
    if code in {
        VerdictCode.high_caution,
        VerdictCode.do_not_start,
    }:
        return 2
    if code in {
        VerdictCode.blocked_region,
        VerdictCode.blocked_account,
        VerdictCode.blocked_service,
        VerdictCode.blocked_clock,
    }:
        return 3
    return 4


def _run_scan(settings: Settings) -> None:
    settings.ensure()
    store = HistoryStore(settings.db_path)
    scanner = TerminalScanner(
        console,
        enabled=not settings.no_anim and not settings.json_stdout,
    )
    try:
        with scanner:
            report = run_scan(settings, store=store, progress=scanner.progress)
    except RuntimeError as exc:
        console.print(Text(str(exc), style="#F43F5E"))
        raise typer.Exit(code=4) from None

    data = _public_dict(report, settings)
    if settings.json_out:
        _write_json(data, settings.json_out)
        if not settings.json_stdout:
            console.print(Text(f"JSON  {settings.json_out}", style="#6B8299"))

    html_path = None
    if settings.html and not settings.json_stdout:
        stamp = report.started_at.astimezone().strftime("%Y%m%d-%H%M%S")
        html_path = settings.reports_dir / f"{stamp}-{report.run_id}.html"
        render_html(report, html_path, settings, store.recent(20))
        latest = settings.reports_dir / "latest.html"
        try:
            shutil.copyfile(html_path, latest)
            latest.chmod(0o600)
        except OSError:
            pass

    if settings.json_stdout:
        sys.stdout.write(json.dumps(data, ensure_ascii=False, indent=2) + "\n")
        sys.stdout.flush()
    else:
        render_report(report, settings, html_path, console=console)

    if settings.open_report and html_path and not settings.json_stdout:
        try:
            webbrowser.open(html_path.as_uri())
        except Exception:
            pass

    raise typer.Exit(code=_exit_code(report.verdict.code))


@app.callback()
def main(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", help="打印版本并退出"),
    json_stdout: bool = typer.Option(False, "--json", help="只输出机器可读 JSON"),
    json_out: Optional[Path] = typer.Option(None, "--json-out", help="把 JSON 写到文件"),
    html: bool = typer.Option(True, "--html/--no-html", help="生成 HTML 报告"),
    open_report: bool = typer.Option(True, "--open/--no-open", help="生成后打开 HTML"),
    show_ip: bool = typer.Option(False, "--show-ip", help="在终端/JSON 中显示完整 IP"),
    no_ip_intel: bool = typer.Option(False, "--no-ip-intel", help="跳过第三方 IP 情报"),
    proxy: Optional[str] = typer.Option(None, "--proxy", help="用指定代理检测同一路径"),
    explain: bool = typer.Option(False, "--explain", help="展开逐条规则与分值"),
    compact: bool = typer.Option(False, "--compact", help="紧凑终端输出"),
    no_anim: bool = typer.Option(False, "--no-anim", help="关闭扫描动画"),
    deep: bool = typer.Option(False, "--deep", help="可选：检查 cron/shell 聚合计数"),
    offline: bool = typer.Option(False, "--offline", help="用上次报告离线重放"),
) -> None:
    if version:
        console.print(f"claude-sentinel {__version__}")
        raise typer.Exit()
    if ctx.invoked_subcommand is not None:
        return
    _run_scan(
        _settings(
            proxy=proxy,
            show_ip=show_ip,
            no_ip_intel=no_ip_intel,
            no_anim=no_anim,
            compact=compact,
            deep=deep,
            explain=explain,
            offline=offline,
            html=html,
            open_report=open_report,
            json_stdout=json_stdout,
            json_out=json_out,
        )
    )


@app.command("scan")
def scan_cmd(
    json_stdout: bool = typer.Option(False, "--json", help="只输出机器可读 JSON"),
    json_out: Optional[Path] = typer.Option(None, "--json-out", help="把 JSON 写到文件"),
    html: bool = typer.Option(True, "--html/--no-html", help="生成 HTML 报告"),
    open_report: bool = typer.Option(True, "--open/--no-open", help="生成后打开 HTML"),
    show_ip: bool = typer.Option(False, "--show-ip", help="在终端/JSON 中显示完整 IP"),
    no_ip_intel: bool = typer.Option(False, "--no-ip-intel", help="跳过第三方 IP 情报"),
    proxy: Optional[str] = typer.Option(None, "--proxy", help="用指定代理检测同一路径"),
    explain: bool = typer.Option(False, "--explain", help="展开逐条规则与分值"),
    compact: bool = typer.Option(False, "--compact", help="紧凑终端输出"),
    no_anim: bool = typer.Option(False, "--no-anim", help="关闭扫描动画"),
    deep: bool = typer.Option(False, "--deep", help="可选：检查 cron/shell 聚合计数"),
    offline: bool = typer.Option(False, "--offline", help="用上次报告离线重放"),
) -> None:
    """与直接运行 sentinel 等价的一键体检。"""
    _run_scan(
        _settings(
            proxy=proxy,
            show_ip=show_ip,
            no_ip_intel=no_ip_intel,
            no_anim=no_anim,
            compact=compact,
            deep=deep,
            explain=explain,
            offline=offline,
            html=html,
            open_report=open_report,
            json_stdout=json_stdout,
            json_out=json_out,
        )
    )


@app.command("live")
def live_cmd(
    host: str = typer.Option("127.0.0.1", "--host", help="监听地址（默认仅本机）"),
    port: int = typer.Option(8765, "--port", min=0, max=65535, help="端口；被占用时自动顺延"),
    open_browser: bool = typer.Option(True, "--open/--no-open", help="自动打开浏览器"),
    app_window: bool = typer.Option(
        True, "--app/--tab", help="优先用 Chrome/Edge 应用窗口打开（录屏更干净）"
    ),
    autostart: bool = typer.Option(True, "--auto/--no-auto", help="页面打开后立即自动检测一次"),
    width: int = typer.Option(1440, "--width", min=640, max=3840, help="应用窗口宽度"),
    height: int = typer.Option(940, "--height", min=480, max=2160, help="应用窗口高度"),
    show_ip: bool = typer.Option(False, "--show-ip", help="在 Web UI 中显示完整 IP"),
    proxy: Optional[str] = typer.Option(None, "--proxy", help="用指定代理检测同一路径"),
    no_ip_intel: bool = typer.Option(False, "--no-intel", help="跳过第三方 IP 情报"),
    deep: bool = typer.Option(False, "--deep", help="可选：检查 cron/shell 聚合计数"),
) -> None:
    """一键打开动效检测面板：自动开窗、自动检测、可随时重新检测。"""
    settings = _settings(
        proxy=proxy,
        show_ip=show_ip,
        no_ip_intel=no_ip_intel,
        deep=deep,
    )
    bound_port = _bindable_port(host, port)
    run_web(
        settings,
        host=host,
        port=bound_port,
        open_browser=open_browser,
        app_window=app_window,
        autostart=autostart,
        width=width,
        height=height,
    )


def _bindable_port(host: str, port: int) -> int:
    """Return a usable port: 0 stays random, busy ports scan forward a little."""
    if port == 0:
        return 0
    import socket

    for candidate in (port, *range(port + 1, min(port + 20, 65536))):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind((host, candidate))
            except OSError:
                continue
            return candidate
    console.print(Text(f"{port}–{port + 19} 都被占用；请用 --port 指定其他端口。", style="#F43F5E"))
    raise typer.Exit(code=1)


@app.command("serve")
def serve_cmd(
    host: str = typer.Option("127.0.0.1", "--host", help="监听地址（默认仅本机）"),
    port: int = typer.Option(8765, "--port", min=0, max=65535, help="端口；0 表示随机"),
    open_browser: bool = typer.Option(True, "--open/--no-open", help="自动打开浏览器"),
    show_ip: bool = typer.Option(False, "--show-ip", help="在 Web UI 中显示完整 IP"),
    proxy: Optional[str] = typer.Option(None, "--proxy", help="用指定代理检测同一路径"),
    no_ip_intel: bool = typer.Option(False, "--no-ip-intel", help="跳过第三方 IP 情报"),
    deep: bool = typer.Option(False, "--deep", help="可选：检查 cron/shell 聚合计数"),
) -> None:
    """启动本地 three.js 动效面板（仅本机）。"""
    settings = _settings(
        proxy=proxy,
        show_ip=show_ip,
        no_ip_intel=no_ip_intel,
        deep=deep,
    )
    run_web(settings, host=host, port=port, open_browser=open_browser)


@app.command("account")
def account_cmd(
    from_claude_code: bool = typer.Option(
        False, "--from-claude-code", help="读取本机 Claude Code OAuth 凭据（macOS Keychain）"
    ),
    token_stdin: bool = typer.Option(False, "--token-stdin", help="从 stdin 读取 OAuth token"),
    cookie_stdin: bool = typer.Option(False, "--cookie-stdin", help="从 stdin 读取 Cookie/sessionKey"),
    user_agent: Optional[str] = typer.Option(None, "--user-agent", help="与 Cookie 匹配的 UA"),
    proxy: Optional[str] = typer.Option(None, "--proxy"),
    as_json: bool = typer.Option(False, "--json", help="输出账号状态 JSON（不含凭据）"),
) -> None:
    """可选：只读探测账号状态。凭据不落盘；结果只缓存状态 24 小时。"""
    settings = _settings(proxy=proxy)
    settings.ensure()
    token: Optional[str] = None
    cookie: Optional[str] = None
    state: Optional[AccountState] = None

    if from_claude_code:
        token, state = read_claude_code_token()
        if state is None and not token:
            console.print(Text("未在 Keychain/本地凭据文件中找到 Claude Code OAuth token。", style="#F59E0B"))
            raise typer.Exit(code=4)
    elif token_stdin:
        token = sys.stdin.read().strip() or None
    elif cookie_stdin:
        cookie = sys.stdin.read().strip() or None
    else:
        value = typer.prompt(
            "粘贴 OAuth token（sk-ant-oat…）或 Cookie/sessionKey",
            hide_input=True,
        ).strip()
        if value.startswith("sk-ant-oat") or value.startswith("sk-ant-ort"):
            token = value
        elif value.startswith("sk-ant-sid") or "sessionKey=" in value or len(value) > 30:
            cookie = value
        else:
            console.print(Text("无法识别凭据格式。", style="#F43F5E"))
            raise typer.Exit(code=4)

    if state is None and not token and not cookie:
        console.print(Text("未提供凭据。", style="#F43F5E"))
        raise typer.Exit(code=4)

    http = Http(proxy=settings.proxy, timeout=10)
    try:
        if state is None:
            state = (
                probe_oauth(token, http, user_agent)
                if token
                else probe_cookie(cookie or "", http, user_agent)
            )
    finally:
        http.close()

    cache_write(settings.cache_dir, "account_state", state.model_dump(mode="json"))
    code = 0 if state.state == "active" else (1 if state.state == "expired" else (3 if state.state in {"disabled", "region_blocked"} else 4))
    if as_json:
        sys.stdout.write(state.model_dump_json(indent=2) + "\n")
        sys.stdout.flush()
        raise typer.Exit(code=code)

    color = {
        "active": "#34D399",
        "expired": "#F59E0B",
        "disabled": "#F43F5E",
        "region_blocked": "#F43F5E",
        "challenge": "#F59E0B",
    }.get(state.state, "#6B8299")
    table = Table(box=None, show_header=False, padding=(0, 1))
    table.add_column(style="#6B8299", width=12)
    table.add_column(style="#E5F2FF")
    table.add_row("STATE", Text(state.state.upper(), style=f"bold {color}"))
    if state.plan:
        table.add_row("PLAN", str(state.plan))
    if state.organization:
        table.add_row("ORG", str(state.organization))
    if state.chat_capable is not None:
        table.add_row("CHAT", "yes" if state.chat_capable else "no")
    if state.detail:
        table.add_row("DETAIL", state.detail)
    table.add_row("CACHE", "状态已缓存 24h（不含凭据）")
    console.print(Panel(table, border_style=color, title="ACCOUNT", title_align="left"))
    raise typer.Exit(code=code)


@app.command("probe")
def probe_cmd(
    timeout: float = typer.Option(150.0, "--timeout", help="等待浏览器提交的秒数"),
    as_json: bool = typer.Option(False, "--json", help="输出探针 JSON"),
    open_browser: bool = typer.Option(True, "--open/--no-open", help="自动打开浏览器"),
) -> None:
    """可选：在真实浏览器中采集时区、WebRTC、Canvas 与浏览器出口 IP。"""
    settings = _settings()
    settings.ensure()
    probe = run_browser_probe(settings, timeout=timeout, open_browser=open_browser)
    if probe is None:
        raise typer.Exit(code=1)
    if as_json:
        sys.stdout.write(probe.model_dump_json(indent=2) + "\n")
        sys.stdout.flush()
        raise typer.Exit()
    table = Table(box=None, show_header=False, padding=(0, 1))
    table.add_column(style="#6B8299", width=14)
    table.add_column(style="#E5F2FF")
    table.add_row("时区", probe.timezone or "—")
    table.add_row("语言", ", ".join(probe.languages) or "—")
    table.add_row("浏览器出口", probe.egress_ip or "—")
    table.add_row("出口地区", probe.egress_country or "—")
    table.add_row("WebRTC", f"{len(probe.webrtc)} 个候选")
    table.add_row("Canvas", (probe.canvas_hash or "—")[:16])
    table.add_row("字体", ", ".join(probe.fonts) or "—")
    console.print(Panel(table, border_style="#22D3EE", title="BROWSER PROBE", title_align="left"))
    console.print(Text("已缓存 15 分钟；现在运行 sentinel 会自动合并。", style="#6B8299"))


@app.command("history")
def history_cmd(
    last: int = typer.Option(10, "--last", "-n", min=1, max=200),
    diff: bool = typer.Option(False, "--diff", help="对比最近两次"),
    as_json: bool = typer.Option(False, "--json"),
    show_ip: bool = typer.Option(False, "--show-ip", help="显示完整历史 IP"),
    clear: bool = typer.Option(False, "--clear", help="清空历史"),
    prune: bool = typer.Option(False, "--prune", help="按保留策略清理"),
) -> None:
    """查看本地历史与漂移。"""
    settings = _settings()
    settings.ensure()
    store = HistoryStore(settings.db_path)

    if clear:
        if typer.confirm("确定清空本地历史？此操作不可恢复。", default=False):
            store.clear()
            console.print(Text("已清空。", style="#34D399"))
        raise typer.Exit()
    if prune:
        store.prune()
        console.print(Text("已按保留策略清理。", style="#34D399"))
        raise typer.Exit()

    rows = store.recent(last)
    if not rows:
        console.print(Text("暂无历史；先运行一次 sentinel。", style="#6B8299"))
        raise typer.Exit()

    if as_json:
        payload = []
        for row in rows:
            item = {k: v for k, v in row.items() if k != "report_json"}
            if not show_ip and item.get("ip"):
                item["ip"] = mask_ip(item["ip"])
            payload.append(item)
        sys.stdout.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
        sys.stdout.flush()
        raise typer.Exit()

    if diff:
        if len(rows) < 2:
            console.print(Text("至少需要两次记录才能对比。", style="#F59E0B"))
            raise typer.Exit(code=1)
        drift = store.compute_drift(rows[0], rows[1])
        changed = [d for d in drift if d.changed]
        if not changed:
            console.print(Text("最近两次没有变化。", style="#34D399"))
        else:
            table = Table(box=None, show_header=True, header_style="#6B8299")
            table.add_column("字段")
            table.add_column("上次")
            table.add_column("本次")
            for item in changed:
                previous = item.previous or "—"
                current = item.current or "—"
                if not show_ip:
                    previous = redact_text(previous)
                    current = redact_text(current)
                table.add_row(item.label, previous, current)
            console.print(table)
        raise typer.Exit()

    short = {
        "不可发起对话": "不可发起",
        "可以，但建议先处理": "可发起*",
        "谨慎发起": "谨慎",
        "不建议发起": "不建议",
        "暂不可发起对话": "暂不可",
        "先校准系统时间": "需校时",
        "无法判断": "未知",
    }
    table = Table(box=None, show_header=True, header_style="#6B8299", expand=False)
    table.add_column("时间", width=11, no_wrap=True)
    table.add_column("结论", width=10, no_wrap=True)
    table.add_column("分", width=4, justify="right", no_wrap=True)
    table.add_column("国家", width=5, no_wrap=True)
    table.add_column("IP", width=17, no_wrap=True)
    table.add_column("时区", width=15, no_wrap=True)
    for row in rows:
        started = row.get("started_at") or ""
        try:
            from datetime import datetime

            started = datetime.fromisoformat(started.replace("Z", "+00:00")).astimezone().strftime("%m-%d %H:%M")
        except ValueError:
            pass
        verdict = str(row.get("verdict") or "—")
        table.add_row(
            str(started),
            short.get(verdict, verdict[:6]),
            "—" if row.get("score") is None else f"{row['score']:.0f}",
            str(row.get("country") or "—"),
            str(row.get("ip_masked") or "—"),
            str(row.get("timezone") or "—"),
        )
    console.print(table)
    console.print(Text("提示：可发起* = 有建议项；完整 ASN/结论用 --json；IP 需 --show-ip。", style="#6B8299"))


@app.command("profile")
def profile_cmd(
    reset: bool = typer.Option(False, "--reset", help="删除画像"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """填写账号画像（可选，只影响账号维度）。"""
    settings = _settings()
    settings.ensure()
    path = settings.profile_path
    if reset:
        if path.exists():
            path.unlink()
        console.print(Text("已删除画像。", style="#34D399"))
        raise typer.Exit()

    existing = load_profile(path) or Profile()
    if as_json:
        console.print(existing.model_dump_json(indent=2), markup=False, highlight=False)
        raise typer.Exit()

    def text_prompt(label: str, current: Optional[str]) -> Optional[str]:
        value = typer.prompt(label, default=current or "").strip()
        return value or None

    def country_prompt(label: str, current: Optional[str]) -> Optional[str]:
        value = text_prompt(label, current)
        if value is None:
            return None
        value = value.upper()
        if len(value) != 2 or not value.isalpha():
            console.print(Text("请输入 ISO2 两位国家码，例如 US / JP / SG。", style="#F43F5E"))
            raise typer.Exit(code=1)
        return value

    signup = country_prompt("注册地区 ISO2（如 US/JP/SG，留空跳过）", existing.signup_country)
    payment = country_prompt("支付方式国家 ISO2", existing.payment_country)
    phone = country_prompt("手机号国家 ISO2", existing.phone_country)
    plan = text_prompt("套餐（free/pro/max/team，留空跳过）", existing.plan)
    age_raw = typer.prompt(
        "账号年龄（月，留空跳过）",
        default="" if existing.account_age_months is None else str(existing.account_age_months),
    ).strip()
    try:
        age = int(age_raw) if age_raw else None
    except ValueError:
        age = None
    shared = typer.confirm("是否共享账号/代充？", default=bool(existing.shared))
    prior = typer.confirm("是否有历史封禁？", default=bool(existing.prior_ban))
    multiple = typer.confirm("是否多账号轮换？", default=bool(existing.multiple_accounts))

    profile = Profile(
        signup_country=signup,
        payment_country=payment,
        phone_country=phone,
        plan=plan,
        account_age_months=age,
        shared=shared,
        prior_ban=prior,
        multiple_accounts=multiple,
    )
    path.write_text(profile.model_dump_json(indent=2), encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    console.print(Text(f"已写入 {path}", style="#34D399"))


@app.command("rules")
def rules_cmd(as_json: bool = typer.Option(False, "--json")) -> None:
    """列出规则、权重和来源。"""
    from claude_sentinel.rules import all_rules

    rules = all_rules()
    if as_json:
        payload = [
            {
                "id": meta.id,
                "title": meta.title,
                "category": str(meta.category),
                "severity": str(meta.severity),
                "max_points": meta.max_points,
                "fix": meta.fix,
                "visibility": str(meta.visibility),
                "sources": [{"name": s.name, "url": s.url} for s in meta.sources],
            }
            for meta, _ in rules
        ]
        sys.stdout.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
        sys.stdout.flush()
        raise typer.Exit()

    table = Table(box=None, show_header=True, header_style="#6B8299", expand=True)
    table.add_column("规则", width=32)
    table.add_column("分类", width=10)
    table.add_column("级别", width=9)
    table.add_column("分值", width=5, justify="right")
    table.add_column("来源", ratio=1)
    for meta, _ in rules:
        table.add_row(
            meta.id,
            str(meta.category),
            str(meta.severity),
            f"{meta.max_points:.0f}",
            ", ".join(s.name for s in meta.sources),
        )
    console.print(table)


@app.command("weights")
def weights_cmd(as_json: bool = typer.Option(False, "--json")) -> None:
    """查看当前权重、版本与设定理由。"""
    data = load_weights()
    if as_json:
        sys.stdout.write(json.dumps(data, ensure_ascii=False, indent=2) + "\n")
        sys.stdout.flush()
        raise typer.Exit()
    console.print(
        Text(
            f"weights v{data.get('version', '?')} · effective {data.get('effective', '?')}",
            style="#22D3EE",
        )
    )
    if data.get("rationale"):
        console.print(Text(str(data["rationale"]), style="#6B8299"))
    table = Table(box=None, show_header=True, header_style="#6B8299", expand=False)
    table.add_column("分类", width=18)
    table.add_column("权重", width=6, justify="right")
    table.add_column("说明", width=14)
    for key, cfg in data.get("categories", {}).items():
        table.add_row(key, str(cfg.get("weight", "—")), str(cfg.get("label", "")))
    console.print(table)


@app.command("sources")
def sources_cmd() -> None:
    """列出会访问的外部数据源。"""
    rows = [
        ("official", "Claude region gate", "https://claude.ai/api/organizations"),
        ("official", "Supported regions", "https://www.anthropic.com/supported-countries"),
        ("official", "Claude status", "https://status.claude.com/api/v2/summary.json"),
        ("official", "OAuth profile (opt-in)", "https://api.anthropic.com/api/oauth/profile"),
        ("edge", "Cloudflare trace", "https://www.cloudflare.com/cdn-cgi/trace"),
        ("registry", "IANA RDAP bootstrap", "https://data.iana.org/rdap/ipv4.json"),
        ("third-party", "ip-api", "http://ip-api.com/json/"),
        ("third-party", "ipapi.is", "https://api.ipapi.is/"),
        ("third-party", "ipinfo", "https://ipinfo.io/"),
        ("third-party", "edns", "https://edns.ip-api.com/json"),
    ]
    table = Table(box=None, show_header=True, header_style="#6B8299", expand=True)
    table.add_column("类型", width=12)
    table.add_column("名称", width=28)
    table.add_column("地址", ratio=1)
    for kind, name, url in rows:
        table.add_row(kind, name, url)
    console.print(table)
    console.print(Text("可选：PROXYCHECK_API_KEY / ABUSEIPDB_API_KEY 用于更丰富的 IP 信誉。", style="#6B8299"))
    console.print(Text("本工具无遥测；除上述查询外不发送数据。", style="#6B8299"))


@app.command("version")
def version_cmd() -> None:
    console.print(f"claude-sentinel {__version__}")


if __name__ == "__main__":
    app()
