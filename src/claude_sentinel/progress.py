"""Scan stages and progress plumbing.

The pipeline emits one event when a stage starts and one when it ends. Renderers
(terminal, live dashboard, JSON) can subscribe without the collectors needing to
know anything about them. A failing progress callback must never break a scan.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from time import perf_counter
from typing import Callable, Iterator, Literal

Phase = Literal["start", "done", "warn", "fail", "skip"]


@dataclass(frozen=True)
class Stage:
    id: str
    label: str
    group: str
    hint: str


STAGES: tuple[Stage, ...] = (
    Stage("gate", "官方区域闸门", "官方信号", "claude.ai 对当前出口的地区判定"),
    Stage("regions", "官方支持地区", "官方信号", "比对官方支持国家/地区列表"),
    Stage("service", "服务状态", "官方信号", "status.claude.com 组件状态"),
    Stage("clock", "系统时钟", "官方信号", "本机与服务器时间偏差"),
    Stage("reach", "官方端点可达性", "官方信号", "claude.ai / api.anthropic.com"),
    Stage("edge", "多域名真实出口", "网络路径", "claude.ai / anthropic.com / api 各自看到的出口"),
    Stage("dual", "双栈路径", "网络路径", "IPv4 与 IPv6 是否走同一出口"),
    Stage("dns", "DNS 解析器", "网络路径", "解析器位置与出口国家是否一致"),
    Stage("local", "本地身份", "本地环境", "时区、语言、中文字体与浏览器"),
    Stage("client", "Claude 客户端", "本地环境", "Claude Code 版本与 API 端点"),
    Stage("ipintel", "IP 信誉情报", "外部情报", "多源共识：机房/代理/Tor/滥用分"),
    Stage("rdap", "注册信息", "外部情报", "RIR 注册网络与分配时间"),
    Stage("rpki", "RPKI 前缀校验", "外部情报", "该前缀的 BGP 起源是否被授权"),
    Stage("account", "账号层", "账号", "只读账号状态（未提供凭据时为参考模式）"),
    Stage("history", "历史与漂移", "历史", "与上次环境逐项对比"),
    Stage("score", "规则评估", "评估", "六轴加权评分与覆盖率"),
    Stage("verdict", "结论生成", "评估", "硬闸门短路与风险区间"),
)

STAGE_BY_ID = {stage.id: stage for stage in STAGES}
TOTAL_STAGES = len(STAGES)

# (stage_id, phase, detail, elapsed_ms)
ProgressFn = Callable[[str, str, str | None, int | None], None]


def stage_public() -> list[dict[str, str]]:
    return [
        {"id": stage.id, "label": stage.label, "group": stage.group, "hint": stage.hint}
        for stage in STAGES
    ]


class _StageHandle:
    """Mutable stage outcome; renderers only see ``phase``/``detail`` on exit."""

    __slots__ = ("phase", "detail")

    def __init__(self, detail: str | None = None) -> None:
        self.phase: Phase = "done"
        self.detail = detail

    def done(self, detail: str | None = None) -> None:
        self.phase = "done"
        if detail:
            self.detail = detail

    def warn(self, detail: str | None = None) -> None:
        self.phase = "warn"
        if detail:
            self.detail = detail

    def skip(self, detail: str | None = None) -> None:
        self.phase = "skip"
        if detail:
            self.detail = detail


class Tracker:
    """Emits stage events; safe to use when nobody is listening."""

    def __init__(self, progress: ProgressFn | None = None) -> None:
        self.progress = progress

    def emit(
        self,
        stage_id: str,
        phase: str,
        detail: str | None = None,
        elapsed_ms: int | None = None,
    ) -> None:
        if self.progress is None:
            return
        try:
            self.progress(stage_id, phase, detail, elapsed_ms)
        except Exception:  # noqa: BLE001 - a UI hiccup must not kill the scan
            return

    @contextmanager
    def stage(self, stage_id: str, detail: str | None = None) -> Iterator[_StageHandle]:
        started = perf_counter()
        handle = _StageHandle(detail)
        self.emit(stage_id, "start", detail, None)
        try:
            yield handle
        except Exception as exc:
            self.emit(stage_id, "fail", str(exc)[:180], _elapsed_ms(started))
            raise
        else:
            self.emit(stage_id, handle.phase, handle.detail, _elapsed_ms(started))


def _elapsed_ms(started: float) -> int:
    return max(1, int((perf_counter() - started) * 1000))
