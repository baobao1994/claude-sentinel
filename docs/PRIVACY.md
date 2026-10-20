# 隐私与数据流（PRIVACY）

## 1. 原则

- **本地优先**：检测在本机完成；没有账号系统、没有遥测、没有云端报告。
- **只读**：对系统、Claude Code 配置和账号只读；只写 `~/.claude-sentinel/`。
- **最小化**：不收集邮箱、姓名、对话内容、Cookie/Token 内容；不读取 Claude 对话正文。
- **可删除**：所有数据都在一个目录里，删掉即可。

## 2. 本地路径

默认 `~/.claude-sentinel/`（可用 `CLAUDE_SENTINEL_HOME` 覆盖）：

| 路径 | 内容 | 权限 |
|---|---|---|
| `sentinel.db` | 历次检测摘要、findings、完整报告 JSON | `0600` |
| `reports/*.html` | 自包含 HTML 报告 | `0600` |
| `cache/` | 支持地区列表、状态页、IP 情报、账号状态、浏览器探针 | 目录 `0700` |
| `device_id` | 随机生成的本地安装 ID（用于稳定指纹，不上传） | `0600` |
| `profile.json` | 你自己填写的账号画像（注册地/支付地等） | `0600` |

默认保留 200 次 / 180 天；`sentinel history --prune` 可清理，`--clear` 可清空。

## 3. 会访问哪些外部服务

| 服务 | 目的 | 发送的数据 | 频率/缓存 |
|---|---|---|---|
| `claude.ai/api/organizations` | 官方区域闸门 | 无 Cookie、无账号数据；普通 HTTP 请求 | 每次检测 |
| `claude.ai/login` | 区域闸门交叉验证 | 无 Cookie | 闸门不确定时 |
| `anthropic.com/supported-countries` | 官方支持地区列表 | 无 | 7 天缓存 |
| `status.claude.com` | 官方服务状态 | 无 | 60 秒缓存 |
| `api.anthropic.com/api/oauth/profile` | 可选账号状态 | 你的 OAuth token（仅在你显式运行 `sentinel account` 时） | 单次，不缓存凭据 |
| `claude.ai/api/organizations`（带 Cookie） | 可选账号状态 | 你的 sessionKey/Cookie（仅显式） | 单次，不缓存凭据 |
| `cloudflare.com/cdn-cgi/trace` | 边缘看到的出口 IP/地区/colo | 你的出口 IP（请求本身必然暴露） | 每次检测 |
| `data.iana.org/rdap` + RIR RDAP | IP 段归属/注册时间 | 查询的 IP | 30 天 bootstrap 缓存 |
| `ip-api.com` | IP 类型/代理/机房/移动 | 查询的 IP（HTTP，明文） | 24 小时缓存 |
| `api.ipapi.is` | IP 归属/公司 | 查询的 IP | 24 小时缓存 |
| `ipinfo.io` | IP 归属/ASN | 查询的 IP | 24 小时缓存 |
| `proxycheck.io` | 可选：代理/VPN/风险分 | 查询的 IP + API key（如设置） | 24 小时缓存 |
| `abuseipdb.com` | 可选：滥用分 | 查询的 IP + API key（如设置） | 24 小时缓存 |
| `edns.ip-api.com` | DNS 解析器 IP/Geo | 你的 DNS 查询（请求本身） | 每次检测 |

> 第三方 IP 情报服务会看到你查询的 IP；这是使用它们的前提。若不想发送，使用 `--no-ip-intel`，代价是覆盖率与置信度下降。

## 4. 账号探测（可选）

`sentinel account` 支持三种输入：

1. `--from-claude-code`：读取本机 Claude Code 的 OAuth 凭据（macOS Keychain 项 `Claude Code-credentials`，或 `~/.claude/.credentials.json`）。
2. `--token-stdin` / `--cookie-stdin`：从 stdin 读取，避免 shell 历史记录。
3. 交互式隐藏输入：`getpass`，不回显。

处理规则：

- 只在内存中使用；**不写入 DB、报告、缓存或日志**。
- 只发一个只读请求；不重试、不发消息、不拉取对话。
- 只缓存**状态**（`active` / `expired` / `disabled` / `region_blocked` / `challenge` / `unknown`）24 小时；缓存里没有凭据。
- 输出只显示状态、套餐、组织名、chat 能力、错误码；不显示 token/Cookie。

## 5. 浏览器探针（可选）

`sentinel probe` 启动 `127.0.0.1` 上的临时服务：

- 页面只把 JSON POST 回 `127.0.0.1`；token 一次性、随机。
- 采集：时区、locale、语言、UA、UA-CH、屏幕、DPR、硬件并发、设备内存、Canvas 哈希、WebGL 信息、字体列表、WebRTC ICE 候选、浏览器出口 IP。
- 外部请求只有两个，页面会明确列出：
  - `https://www.cloudflare.com/cdn-cgi/trace`：获取浏览器出口 IP/地区；
  - 公共 STUN（Google / Cloudflare）：收集 WebRTC 候选。
- 不读取 Cookie、浏览历史、账号内容；不持久化 Canvas 图像。

## 6. 本地 Web UI（可选）

`sentinel serve` 启动本地面板：

- 默认只监听 `127.0.0.1`；不建议 `--host 0.0.0.0`。
- 每次启动生成一次性 token，注入页面；`POST /api/scan` 同时校验 token 与 `Origin`。
- 不发送 CORS 头，其他网站无法读取 API。
- three.js 已随 wheel 本地打包，不访问 CDN。
- 页面读取的 `/api/latest`、`/api/history` 默认脱敏；`--show-ip` 才返回完整 IP。
- 扫描仍在本机执行，数据不离开本机。

## 7. deep 模式（可选）

`sentinel --deep` 只统计：

- `cron` / `launchd` 中包含 `claude` 的任务数；
- `~/.zsh_history` / `~/.bash_history` 中 `claude` + `for/xargs/while` 的行数；
- `~/.claude/projects/` 下会话文件数量与总大小；
- 从 JSONL 的 `timestamp` 字段计算最大请求/分钟（只提取时间戳，不保存消息内容）。

不保存命令行内容、对话内容或文件路径列表。

## 8. 分享与脱敏

- HTML 报告、Web UI、JSON 默认使用 `203.0.*.*` / `2001:db8:…` 形式。
- 终端默认显示完整 IP（本机屏幕）；`--show-ip` 让 HTML/JSON 也显示完整值。
- 报告里的 `sources` 可能包含你查询过的 URL；分享前请自行检查。
- 清除数据：

```bash
sentinel history --clear
rm -rf ~/.claude-sentinel
```

## 9. 不做的事

- 无统计、广告、追踪脚本；不从 CDN 加载资源。
- 不上传报告、历史或设备指纹。
- 不读取 Claude 对话正文；不保存账号密码。
