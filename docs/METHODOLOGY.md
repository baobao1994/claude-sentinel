# 判定方法（METHODOLOGY）

## 1. 什么叫“权威”

本工具把结论拆成四层，**每一层都标来源，不混用**：

| 层级 | 例子 | 能说明什么 | 不能说明什么 |
|---|---|---|---|
| `official` | `claude.ai/api/organizations` 的 `region_unavailable`、`status.claude.com`、官方支持地区页、OAuth profile | 当前路径/账号的官方状态 | 不包含内部风控、黑名单、支付历史 |
| `registry` | IANA RDAP bootstrap + RIR RDAP | IP 段归属、注册时间、滥用联系人 | 不能判断该 IP 是否被 Anthropic 标记 |
| `edge` | Cloudflare `cdn-cgi/trace` | Claude 边缘实际看到的出口 IP / 地区 / colo | 不是 Anthropic 的账号判断 |
| `third_party` | ip-api、ipapi.is、ipinfo、proxycheck、AbuseIPDB | 代理/VPN/机房/滥用分等画像 | 各家结论可能不一致 |
| `local` | 时区、语言、字体、浏览器、Claude Code 配置 | 本机一致性 | 只有部分信号会被 Claude 看到 |
| `self_report` | 注册地/支付地/共享情况问卷 | 账号背景 | 低置信，仅作上下文 |

报告里的 `SERVER` / `BROWSER JS` / `LOCAL` 徽章对应“Claude 能看到什么”：

- `SERVER`：请求到达 Claude 时可见（IP、TLS、UA、请求头）。
- `BROWSER JS`：claude.ai 页面里的 JS 可读（时区、语言、Canvas、字体、WebRTC）。
- `LOCAL`：只在本机（已安装浏览器、shell 历史、Claude Code 配置），不直接上传。

**本工具不能读取 Anthropic 的内部风控规则、黑名单、支付记录或服务端历史。** 所以“安全分”是启发式，不是封号概率；“账号是否被封”只有官方账号接口/页面给出 `disabled` 时才算事实。

## 2. 官方闸门（硬判定，先于评分）

按顺序：

1. **账号停用**：`sentinel account` 探测到 `disabled`。
2. **区域限制**：`GET https://claude.ai/api/organizations`（无 Cookie）返回 `403` 且 `error.details.error_code == region_unavailable`；或登录页 302 到 `app-unavailable-in-region`；或出口国家不在官方支持列表。
3. **服务异常**：`status.claude.com` 的 claude.ai / API / Claude Code 组件非 `operational`。
4. **时钟偏差**：HTTP `Date` 与本机相差 > 300 秒。
5. **无法判断**：关键数据源全部不可达、Cloudflare 挑战、出口国家未知、或总体覆盖率 < 60%。

闸门命中时，报告仍保留完整证据和修复步骤，但安全分显示 `—`，避免“硬阻断却给一个看似精确的分数”。

### 关于区域闸门

无 Cookie 的 `claude.ai/api/organizations` 在不同路径下会返回：

- `200`：地区可用（通常还会返回组织列表，但本工具不依赖内容）；
- `401` / `403 account_session_invalid`：地区可用，只是未登录/会话无效；
- `403 region_unavailable`：当前路径所在地区不受支持；
- `403 cf-mitigated: challenge` / HTML：Cloudflare 拦截，结论为未知。

官方支持地区页当前为统一列表（185 个国家/地区，页面标注生效日期 2026-11-12；不含中国大陆、香港、澳门、俄罗斯，台湾在列）。运行时抓取并缓存 7 天；抓取失败使用内置快照并标记 `stale`。

## 3. 评分

每条规则声明 `max_points`。规则状态到分值的映射：

| 状态 | 倍率 |
|---|---:|
| `ok` | 0 |
| `info` | 0（不参与评分） |
| `warn` | 0.6 |
| `high` | 1.0 |
| `unknown` | 0（从分母中剔除，但降低覆盖率） |

分数是**安全分**：100 = 最干净，0 = 最糟。`points` 累计的是风险点，所以取补：

```
risk_ratio     = Σ(points) / Σ(possible)
category_score = 100 − risk_ratio × 100
overall        = Σ(category_score × weight × coverage) / Σ(weight × coverage)
```

两个细节决定这个数能不能信：

1. **按覆盖率比例计入权重，而不是设 0.5 硬门槛。** 早期实现在分类覆盖率 < 0.5 时整类丢弃，
   于是一次 RDAP 超时就让权重 30 的 `ip` 分类消失，总覆盖率跌破 60%，结论退化成「无法判断」。
   同一台机器连跑三次测得 57% / 57% / 84%。现在部分测到的分类按比例计入，三次稳定在 83–86%。
2. **单条严重发现封顶，不被平均稀释。** 分类内平均会把一条满分命中摊薄：40/40 的时区不匹配
   在 150 分预算的分类里只剩 26.7%，总分 9/100，与「人就站在 CN、正用 SG 出口」这个事实矛盾；
   出口是 Tor 时总分只有 14。现在 `critical`/`high` 命中按命中比例把分类与总分的上限压到
   38 / 60，两者取较低者。环境全干净时仍是 100。

`score_basis` 字段记录算式：
`{"averaged": 73.0, "cap": 38.0, "cap_rule": "stability.runtime_split", "cap_severity": "critical", "capped": true}`
——终端、HTML 与 UI 都会把它显示出来。

总体覆盖率 < 60% 或出口国家未知时，结论为「无法判断」，并逐条列出缺什么、怎么补。

等级（`weights.yaml` 可调）：

| 分数 | 等级 |
|---:|---|
| 86–100 | 低 |
| 66–85 | 中 |
| 41–65 | 高 |
| 0–40 | 极高 |

历史分数在升级时**一次性反转**旧记录（旧 9 → 新 91），并在 `score_scale` 列标记为 `safety`，
避免新旧两种口径混在同一张趋势图里。

置信度：

- 高：总体覆盖率 ≥ 80%，且 IP 情报至少 2 个数据源可用；
- 中：覆盖率 50–79%，或账号层未验证；
- 低：覆盖率 < 60%，或关键闸门无法判断。

## 4. 权重（v1，启发式）

| 分类 | 权重 | 说明 |
|---|---:|---|
| 网络出口与信誉 | 30 | 机房/VPN/代理/Tor、滥用分、IP 类型、RDAP 注册时间 |
| 本地身份一致性 | 20 | 时区/语言 vs 出口、DNS 解析器、中文字体/浏览器（弱信号） |
| 客户端与中转 | 20 | `ANTHROPIC_BASE_URL`、第三方中转、认证混用、旧版标记区间 |
| 出口稳定性 | 12 | IP/ASN/国家漂移、双栈不一致、浏览器 vs 终端出口 |
| 账号画像 | 10 | 自报共享/多账号/历史封禁/支付地/注册地 |
| 行为模式 | 8 | 可选 deep：会话频率、cron、shell 批量调用 |

权重不是官方算法，也不代表概率。v2 的判断依据是：**IP 信誉与官方区域闸门最可验证，客户端中转最可操作，稳定性容易受网络波动影响，账号自报与 deep 行为置信度最低**。`sentinel rules` 可列出所有规则；`sentinel --explain` 可展开每条规则的证据与分值。

## 5. 关键词与阈值

- **IP 类型**：优先 `ip-api` 的 `proxy` / `hosting` / `mobile`，`proxycheck`（可选 key）的 `type` / `risk`，`AbuseIPDB`（可选 key）的 `abuseConfidenceScore`；多源不一致时并列显示，不替用户选边。
- **IP 稳定性**：本地历史中 1 小时/24 小时/7 天的不同 IP、ASN、国家数量；1 小时内跨国跳变单独高亮。
- **时区/语言**：`Asia/Shanghai`、`Asia/Urumqi` 等映射到 CN；只有**主 locale/语言**为中文时才与出口国家比较，避免把“系统里有中文语言包”误判为中文环境。
- **DNS**：`edns.ip-api.com` 返回的解析器 IP/Geo 与 HTTP 出口国家比较；这是“分流是否完整”的提示，不等同于 DNS 泄漏证明。
- **双栈**：分别用 `curl -4/-6` 请求 Cloudflare trace；国家不同 → 高；同国但 ASN 不同 → 提醒。
- **客户端**：`ANTHROPIC_BASE_URL` 非 `api.anthropic.com`/`*.anthropic.com` → 第三方中转；Claude Code `2.1.91–2.1.196` 属于 2026-06 逆向分析的旧标记区间，`2.1.197` 起已移除，仅作历史信息。
- **行为（deep）**：只统计 cron/launchd 中包含 `claude` 的任务数、shell 历史中 `claude` + `for/xargs/while` 的行数、会话文件数量/大小，以及从时间戳计算的最大请求/分钟（>60 高、>30 提醒）；不保存命令或对话内容。

## 6. 已知局限

- 无法读取 Anthropic 内部风控/黑名单/支付/服务端历史。
- 本部署默认是**参考模式**：没有账号凭据时，账号层只作参考，报告只代表环境评估。账号层必须显式提供凭据；`sessionKey` 可能被 Cloudflare 挑战，OAuth profile 在部分网络也可能返回 `403 Request not allowed`；这些情况一律标为「未知」，不当作封号。
- 第三方 IP 情报可能不可达（本机实测 `ipapi.is/json/` 502、`proxycheck.io` 连接失败），报告会显示可用源数量与覆盖率。
- 时区/语言/字体是弱信号，不能单独决定结论。
- 任何“修复”都不会自动改系统；不受支持地区不提供规避方案。
- 工具不能替代官方申诉与官方状态页。

## 7. 参考

- [Anthropic Supported countries and regions](https://www.anthropic.com/supported-countries)
- [Claude Status API](https://status.claude.com/api/v2/summary.json)
- [Claude Code prompt steganography（thereallo.dev，2026-06）](https://thereallo.dev/blog/claude-code-prompt-steganography)
- [claude-analysis（AGPL-3.0，方法论参考）](https://github.com/Nooobhh/claude-analysis)
- [claude-ban-risk-check（9 项权重/IP 历史，方法论参考）](https://github.com/fourierwang66666/claude-ban-risk-check)
- [FK Claude 的可见性分层](https://claude.flowlab.im/)
