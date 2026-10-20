# Changelog

## 0.8.0 — 2026-10-20

分数改为**安全分**（100 = 最干净，越高越安全），并同步修正分类层面的稀释。

- **方向反转**：`RISK / 100` 改为 `SAFETY / 100`。等级改为
  `86–100 低`、`66–85 中`、`41–65 高`、`0–40 极高`。
- **严重项封顶**：原「下限」随之变成「上限」——`critical` 命中把总分压在 38、
  `high` 压在 60（按命中比例插值），两者取较低者。全干净仍是 100。
- **分类同样封顶**：`稳定性` 曾显示 70，而其中明明有一条 `runtime_split`
  critical。现在分类分数也按其内部最严重项封顶，显示 38。
- **分类进度条按自身等级着色**：之前统一用全局 accent，导致 100 分的
  「客户端」也显示红色。
- **历史数据一次性迁移**：旧风险分入库的记录（如 62.0 / 12.8）自动反转为
  38.0 / 87.2，`score_scale` 标记为 `safety`，重复打开不会二次反转。
  迁移后分数仍落在原结论对应的等级里（有测试锁定该一致性）。
- 测试 168 项（新增 8 项：迁移、分类封顶、fixture 与配置一致性）。

## 0.7.0 — 2026-10-20

修掉「分数为什么这么低」——严重问题被平均稀释了。

- **严重度下限**：原模型用 `earned / possible` 算类内分。一条 40/40 的满分
  命中，因为同分类里其他规则「通过」占满分母，只剩 26.7%，最终总分 9。
  「人就站在 CN、正在用 SG 出口」这样明确的问题，被算成了低风险。
  现在 `critical`/`high` 的命中会给总分设下限：Tor 出口单独即 62，
  时区不匹配单独即 40。全干净仍是 0 分。
- **分数可审计**：报告新增 `score_basis`，终端 / HTML / Web UI 都会写明
  「六轴加权平均 28；但 stability.runtime_split（critical）决定下限 62，
  取较高者」。分数不再是黑箱。
- **明确方向**：UI 显示 `RISK / 100 · 越低越安全`，终端显示「风险分，越低越安全」。
- 测试 160 项（新增 5 项评分下限测试）。

## 0.6.0 — 2026-10-20

修掉「报告总是无法判断」——问题不在网络，在判定逻辑。

- **一次抖动不再让整类数据作废**：原逻辑要求某分类覆盖率达到 0.5 才计入
  加权，否则整类丢弃。`ip` 分类权重 30（最高），RDAP 偶发超时就让它的覆盖率
  从 1.0 掉到 0.49，于是整个分类被剔除，总覆盖率跌破 60%，结论退化为
  「无法判断」。现在按实测覆盖率**按比例**计入权重：部分测到的分类仍然提供
  证据，只是权重按比例缩小。实测三次连跑从「57%/57%/84% 抖动」变为
  「86%/86%/83% 稳定」。
- **按需重试**：`Http.fetch()` 对传输层错误重试 2 次（指数退避），19 处
  采集调用全部改用它。HTTP 错误码不重试——重试也改变不了答案。
- **「无法判断」给出可执行方案**：不再只说「检查网络」，而是逐条列出
  「缺什么 → 怎么补」，例如「缺 官方区域闸门不可达 → 在浏览器打开 claude.ai
  确认能正常加载；若它被拦截，闸门与状态页都会失败」。
- 评分语义变更同步更新测试。
- 测试 155 项。

## 0.5.1 — 2026-10-20

修正在真实 TUN 环境下暴露的三个检测错误。

- **TUN 检测对 Clash 类客户端完全失效**：它们用 `0.0.0.0/1` + `128.0.0.0/1`
  两条半区路由接管流量，**不改默认路由**。我们读 `route get default` 只能
  看到物理网卡 `en0`，于是把「TUN 正在接管全部流量」误报成「仅系统代理」。
  改为探测真实外部目的地（`route get 1.1.1.1`）判断实际出口。
- **DNS 泄露误报**：配置里的 nameserver 是国内地址（如 223.6.6.6）并不代表
  泄露——TUN 的 fake-ip 会劫持查询，返回 198.18.x.x 占位地址，真正的解析
  在代理端完成。现在采集并检查**解析结果**：返回 fake-ip 即判定已接管。
  同时修正 `TUN 已开但 DNS 未走隧道` 用同一份证据，不再凭 nameserver 猜测。
- **`addr in [network, ...]` 是 Python 陷阱**：列表成员判断走的是相等比较，
  不是网络包含，导致 fake-ip 检测永远返回 False。改为 `any(addr in n for n ...)`，
  并加回归测试锁死。
- 探测失败重试一次；UI 把「探测失败」与「出口不一致」区分开，避免网络抖动
  被读成环境问题。
- 测试 155 项（新增 12 项）。

## 0.5.0 — 2026-10-20

补上「Claude Code 到底从哪出去」——这是本轮最重要的一条。

- **分运行时实测出口**（`collectors/runtimes.py`）：从 Node（Claude Code 的
  运行时）与 curl 各自请求 `claude.ai/cdn-cgi/trace`，测量各自真实出口。
  实测：浏览器/四个域名全在 SG，而 **Node 在 CN** —— 因为 Node 不读
  macOS 系统代理，只认 `HTTPS_PROXY` 环境变量，而它是空的。也就是说
  Claude Code 一直在直连。新增 `stability.runtime_split`（高危）与
  `stability.runtime_no_proxy_env`（提醒）。
- **多路出口面板**：结果页并排列出每个域名、Node、Shell 的出口；
  不一致时整块高亮并给出提示。
- 修复 Node 探测的两个坑：`-e` 内联脚本会受项目 `package.json`
  (`type: module`) 影响，改用临时 `.cjs`；Happy Eyeballs 在没有 IPv6
  路由时会抛 `AggregateError`，改为 `family: 4` 并把真实
  `ECONNREFUSED/timeout` 原因回传，而不是笼统失败。
- 测试 143 项（新增 22 项）。

## 0.4.0 — 2026-10-20

响应外部专家意见，补上代理与泄露相关的检测维度。

- **多域名真实出口**：分别探测 `claude.ai` / `anthropic.com` /
  `api.anthropic.com` / `cloudflare.com` 的 `/cdn-cgi/trace`。此前只用
  `cloudflare.com`，而分流规则是按域名写的——通用域名显示 SG 干净、
  `claude.ai` 实际看到 CN，会误报「安全」。claude.ai 不可达时按
  anthropic.com → api → cloudflare 依次降级，并在报告里注明依据。
- **TUN vs 系统代理**（`collectors/netmode.py`）：读默认路由与
  `scutil --proxy`，判断流量是被 TUN 接管还是仅系统代理。系统代理模式不会
  覆盖终端里的 curl/Node/Claude Code，这是「代理没弄好」最常见的原因。
- **DNS 泄露**：对比系统解析器与出口国家。实测可抓到「出口在国外、DNS 仍是
  国内运营商」的组合——这正是「一检查就知道你翻墙」的常见成因。
- **WebRTC 泄露**：之前采集了候选地址却零规则消费，现在比较 WebRTC 公网
  候选与浏览器出口，直连暴露即报高危。
- **RPKI 前缀校验**：RIPEstat 两步查询（IP → 前缀+ASN → 校验），
  与 **ASN 类型**（backbone/isp/hosting）一起作为事实字段。
- 修复：并发写入 IP 缓存时共用同一个 `.tmp` 导致互相覆盖；
  终端 HUD 在阶段直接失败时窗口跳到列表末尾；
  国内 DNS 判定在缺少探针数据时提前返回、永远判为「干净」。
- 测试 121 项（新增 23 项）。

## 0.3.0 — 2026-10-20

- **双击启动**：`sentinel-live.command`，首次运行自动装依赖，用 Chrome/Edge
  应用窗口开面板（无地址栏，适合录屏），打开即自动检测；`sentinel.sh` 为终端入口。
- **`sentinel live`**：新命令；端口被占用自动顺延，`--app/--tab`、`--auto/--no-auto`、
  `--width/--height` 可调。
- **真实进度而不是假动画**：`progress.py` 定义 16 个检测阶段，pipeline 逐阶段上报，
  Web 端通过 `POST /api/scan/stream`（SSE）接收；终端同样可用。
- **动效面板重做**：雷达扫描仪 + 扫描光束 + 网格 + 百分比、阶段列表自动居中滚动、
  阶段完成雷达脉冲、数字滚动、仪表环 SVG 描边、六轴条与发现列表逐条入场、结果揭示闪光；
  触发「重新检测」按钮或按 **R** 键即可重跑。
- 无数据轴（如未探测的账号/行为）显示为斜纹轨道，不再像断掉的进度条；
  硬闸门短路时仪表显示 `GATE` 而不是留空。
- 新增 17 个测试（阶段事件、SSE 流、并发扫描拒绝、启动器脚本、应用窗口启动），共 71 个。

## 0.2.0 — 2026-10-20

- Local three.js dashboard: `sentinel serve` (WebGL wireframe globe/starfield,
  animated gauge, live scan, history).
- Weights v2: IP 30 / identity 20 / client 20 / stability 12 / account 10 /
  behavior 8, with documented rationale.
- Reference mode: without account credentials the report explicitly says the
  account layer is unverified; no claims about ban status.
- `account` / `probe` JSON output, `probe --no-open`, `scan` alias.
- History JSON/diff redaction, session-rate deep check, phone/age rules,
  stronger probe token/referrer handling, status fallback, CI + ruff.
- 54 tests.

## 0.1.0 — 2026-10-19

Initial release.

- Five-layer scan: official region gate, egress/IP reputation, stability,
  local identity, Claude Code client, optional account state.
- Hard gates for official region restriction, disabled account, service
  outage, clock skew, and insufficient data.
- Source-tiered findings with remediation, visibility (`server` / `browser_js`
  / `local`), confidence, and coverage.
- SQLite history with per-field drift, churn counts, and a “last environment”
  summary.
- Rich terminal HUD and a self-contained HTML report with radar, gauge,
  visibility matrix, history sparkline, and filters.
- Optional localhost browser probe (timezone, Canvas, WebGL, fonts, WebRTC,
  browser egress IP).
- Optional read-only account probe (OAuth token or claude.ai Cookie), with
  credential-free 24h state cache.
- `--json` / `--json-out` machine output with IP redaction and no raw provider
  payloads.
- 52 tests covering parsers, gates, scoring, verdict, history, redaction,
  account parsing, HTML, CLI, and a fully mocked scan.
