#!/bin/bash
# Claude Sentinel · 一键动效检测面板（双击即可运行）
#
# 双击这个文件：自动准备环境 → 启动本地面板 → 打开应用窗口 → 自动开始检测。
# 之后在面板里点「重新检测」（或按 R 键）就能再跑一次。
#
# 可选参数（终端里运行 ./sentinel-live.command --help 查看全部）：
#   --tab        用普通浏览器标签页打开，而不是应用窗口
#   --no-open    只启动服务，不自动打开窗口
#   --port 8899  指定端口（默认 8765，被占用会自动顺延）
#   --show-ip    在面板中显示完整 IP（默认脱敏）

set -u

cd "$(dirname "$0")" || exit 1
ROOT="$(pwd)"

say() { printf '\033[36m▸\033[0m %s\n' "$*"; }
warn() { printf '\033[33m!\033[0m %s\n' "$*"; }
fail() { printf '\033[31m✕\033[0m %s\n' "$*"; }

printf '\n\033[1;36m  ◈ CLAUDE SENTINEL\033[0m  \033[2mlocal · read-only · live\033[0m\n\n'

# ---------------------------------------------------------------- venv / deps
PY="$ROOT/.venv/bin/python"
if [ ! -x "$PY" ] || ! "$PY" -c 'import claude_sentinel' >/dev/null 2>&1; then
  if command -v uv >/dev/null 2>&1; then
    say "首次运行：正在准备环境（约 10 秒）…"
    UV_CACHE_DIR="$ROOT/.uv-cache" uv sync --quiet || { fail "环境准备失败：uv sync"; exit 1; }
  else
    fail "没有找到 uv，也没有可用的 .venv。请先安装 uv："
    echo "    curl -LsSf https://astral.sh/uv/install.sh | sh"
    exit 1
  fi
fi
if [ ! -x "$PY" ] || ! "$PY" -c 'import claude_sentinel' >/dev/null 2>&1; then
  fail "Python 环境不可用。请在项目目录执行：uv sync"
  exit 1
fi

# ------------------------------------------------------------ run the panel
say "启动本地动效面板…  （关闭本窗口即停止服务）"
echo

exec "$PY" -m claude_sentinel live "$@"
