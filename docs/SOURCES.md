# 数据源与复用清单（SOURCES）

## 官方 / 登记数据

| 数据源 | 用途 | 认证 | 备注 |
|---|---|---|---|
| `https://claude.ai/api/organizations` | 区域闸门；带 Cookie 时是账号组织列表 | 无 / 可选 Cookie | 内部 Web API，可能变化；有登录页 302 兜底 |
| `https://claude.ai/login` | 区域闸门交叉验证 | 无 | `302 → claude.com/app-unavailable-in-region` |
| `https://www.anthropic.com/supported-countries` | 官方支持地区列表 | 无 | 动态抓取 + 7 天缓存 + 内置快照 |
| `https://status.claude.com/api/v2/summary.json` | 官方服务状态 | 无 | Statuspage 格式；60 秒缓存 |
| `https://api.anthropic.com/api/oauth/profile` | 可选账号状态 | OAuth Bearer | 仅 `sentinel account --from-claude-code` / `--token-stdin` |
| `https://data.iana.org/rdap/ipv4.json` / `ipv6.json` | RDAP bootstrap | 无 | 30 天缓存 |
| RIR RDAP（APNIC/ARIN/RIPE 等） | IP 段归属/注册时间/滥用联系人 | 无 | 通过 bootstrap 选择 |

## 边缘 / 网络

| 数据源 | 用途 | 认证 | 备注 |
|---|---|---|---|
| `https://www.cloudflare.com/cdn-cgi/trace` | 出口 IP / loc / colo / warp / tls | 无 | CORS `*`，浏览器探针也可用 |
| `https://edns.ip-api.com/json` | DNS 解析器 IP / Geo | 无 | 结果可能随解析器变化 |
| 公共 STUN（`stun.l.google.com:19302`、`stun.cloudflare.com:3478`） | WebRTC 候选 | 无 | 仅在浏览器探针中 |

## 第三方 IP 情报

| 数据源 | 用途 | 认证 | 免费额度/备注 |
|---|---|---|---|
| `http://ip-api.com/json/{ip}` | 国家/城市/ASN/proxy/hosting/mobile | 无 | 免费非商用；HTTP 明文；45 次/分钟 |
| `https://api.ipapi.is/?q={ip}` | 国家/城市/ASN/公司 | 无 | 免费层字段较少；可加 key 提升 |
| `https://ipinfo.io/{ip}/json` | 国家/城市/ASN | 无 | 免费层基础字段 |
| `https://proxycheck.io/v2/{ip}` | 代理/VPN/Tor/风险分 | 可选 `PROXYCHECK_API_KEY` | 免费额度有限；本机实测可能不可达 |
| `https://api.abuseipdb.com/api/v2/check` | 滥用分/举报数 | 可选 `ABUSEIPDB_API_KEY` | 需要 key |

## 前端依赖

| 依赖 | 版本 | 许可 | 用途 |
|---|---|---|---|
| [three.js](https://threejs.org/) | 0.169.0 | MIT | 本地 Web UI 的 3D 线框球/星场；文件内置于 `web/static/`，不访问 CDN |

## 方法论参考（未复制代码）

| 项目 | 借鉴点 | 许可/说明 |
|---|---|---|
| [claude-analysis](https://github.com/Nooobhh/claude-analysis) | 多源并列、不替用户选边、隐私最小化、出口一览 | AGPL-3.0；仅借鉴思路 |
| [claude-ban-risk-check](https://github.com/fourierwang66666/claude-ban-risk-check) | 9 项本机体检权重、IP 历史 JSONL、分项修复文案 | 仓库未附 LICENSE；仅借鉴思路 |
| [FK Claude](https://claude.flowlab.im/) | “Claude 能看到什么”的可见性分层 | 闭源；仅借鉴思路 |
| [CheckCC](https://checkcc.org/) | 地区画像、Web/Pro/API 分场景 | 闭源；仅借鉴思路 |
| [IPPure](https://ippure.com/claude) / [IP123](https://ip123.in/claude-ai/) / [CleanIP](https://cleanip.io/claude/login) | 检测项清单、历史记录、登录异常分诊 | 仅借鉴思路 |
| [thereallo.dev](https://thereallo.dev/blog/claude-code-prompt-steganography) | Claude Code 旧版标记区间（2.1.91–2.1.196） | 公开逆向分析；只做历史信息 |
| [claude-anti-ban](https://github.com/jaysu66/claude-anti-ban) / [ccmiss](https://github.com/meliwanx/ccmiss) | 设备连续性/出口一致性的事实 | 规避导向；**不采用其规避做法** |

## 许可

本项目 MIT。第三方 API 的使用受各自条款约束；请遵守其免费额度与非商用限制。
