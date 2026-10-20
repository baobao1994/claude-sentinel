#!/bin/bash
# Claude Sentinel · 终端版一键检测（带扫描动画）
#
# 双击无法在终端里运行，所以这里是命令行入口：
#   ./sentinel.sh              完整检测 + 终端 HUD + HTML 报告
#   ./sentinel.sh --no-open    只打印，不打开 HTML 报告
#   ./sentinel.sh live         动效面板（等同 sentinel-live.command）
#
# 想要「双击就能看动画」的版本 → 双击 sentinel-live.command

set -u
cd "$(dirname "$0")" || exit 1
ROOT="$(pwd)"

PY="$ROOT/.venv/bin/python"
if [ ! -x "$PY" ] || ! "$PY" -c 'import claude_sentinel' >/dev/null 2>&1; then
  if command -v uv >/dev/null 2>&1; then
    printf '\033[36m▸\033[0m 首次运行：正在准备环境…\n'
    UV_CACHE_DIR="$ROOT/.uv-cache" uv sync --quiet || exit 1
  else
    printf '\033[31m✕\033[0m 找不到 uv；请先安装：curl -LsSf https://astral.sh/uv/install.sh | sh\n'
    exit 1
  fi
fi

if [ "$#" -gt 0 ] && [ "$1" = "live" ]; then
  shift
  exec "$PY" -m claude_sentinel live "$@"
fi

exec "$PY" -m claude_sentinel "$@"
