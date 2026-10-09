# ARTEX 知识库

本目录收录 ARTEX 的知识文档。2026-10-09 从
[dsh-redteam-mode](https://github.com/Jueze-2019/dsh-redteam-mode)
合并了红队知识库与技能库（见下方“来源说明”）。

## 知识文档

| 文档 | 内容 |
| --- | --- |
| [漏洞流量证据.md](漏洞流量证据.md) | 漏洞流量证据说明（ARTEX 原有） |
| [POC-EXP知识库.md](POC-EXP知识库.md) | POC/EXP 知识库设计：全局共享跨靶标复用、自建库+nuclei 模板库两层同搜、14 归类、三维度溯源筛选 |
| [红队工具调研-2026.md](红队工具调研-2026.md) | 五类红队智能体常用工具调研：信息收集 / 资产梳理 / 漏洞发现 / 漏洞利用 / 内网渗透（GitHub 实测数据，2026-09-20） |
| [得分规则-合并版.md](得分规则-合并版.md) | 突破入侵类得分规则（合并版） |
| [详细文档.md](详细文档.md) | DSH RedTeam 模式详细文档 |
| [项目学习指南.md](项目学习指南.md) | DSH RedTeam 项目学习指南 |
| [kimi-webbridge-setup.md](kimi-webbridge-setup.md) | Kimi WebBridge 环境配置（Linux 桌面机） |
| [npm-2fa-passkey-setup.md](npm-2fa-passkey-setup.md) | npm 验证器换成云同步 passkey 配置指南 |
| [marketplace.md](marketplace.md) | 上架插件市场（dshmarket）说明 |
| [prompt-fix-a-batch.md](prompt-fix-a-batch.md) | 提示词精准手术（A 批次）改动说明 |

## 技能库

红队技能位于仓库根目录 [`skills/`](../skills/)，ARTEX 服务端通过
`skill.LoadDir` 按“每个子目录 = 一个技能、目录内 `SKILL.md` 为技能定义”
的方式加载。本次合并新增 23 个技能：

| 技能 | 用途 |
| --- | --- |
| `active-scan` | 主动端口与服务扫描（nmap/masscan），严格遵守授权范围 |
| `asset-correlation` | 资产关联：域名↔IP↔C 段↔证书↔服务的图谱化 |
| `browser-automation` | 无依赖驱动 Chrome/Chromium 抓取 JS 渲染页面、截图、执行 JS、抓接口清单 |
| `chisel-tunnel` | chisel 隧道：HTTP/WebSocket 封装的多路复用隧道，易穿透出网限制与反向代理 |
| `cn-proxy-pool` | 国内免费 HTTP/SOCKS5 代理池：抓取、验活、按需轮换 |
| `credential-attack` | 凭据攻击：在线弱口令爆破（hydra）与离线哈希破解（hashcat/john） |
| `dir-bruteforce` | 目录与文件爆破：后台入口、备份文件、配置泄露、源码暴露 |
| `fofa-recon` | FOFA API 批量测绘靶标资产（域名/IP/端口/标题/指纹），内置限速避免触发 45012 |
| `frp-tunnel` | frp 内网穿透：VPS 跑 frps、目标跑 frpc，得到稳定 socks5 与端口映射 |
| `fscan-intranet` | fscan 内网综合扫描：存活探测、弱口令爆破、未授权访问与高危漏洞、SOCKS5 隧道 |
| `gogo-intranet` | gogo 高性能内网扫描引擎：主动+被动指纹、关键信息提取、nuclei 模板 POC |
| `kimi-webbridge` | Kimi WebBridge 驱动用户真实 Chrome：导航、读取页面、点击、填表、执行 JS、截图 |
| `lateral-movement` | 内网横向与提权：Impacket 套件（PtH/PsExec/WMI/Kerberos/凭据转储）+ 信息枚举 |
| `nuclei-scan` | nuclei 模板化漏洞扫描：13,000+ 模板覆盖 CVE/暴露面/配置缺陷/默认口令 |
| `passive-recon` | 被动信息收集：不接触目标主机，仅使用公开数据源 |
| `recon-pipeline` | ProjectDiscovery 信息收集流水线：subfinder→dnsx→naabu→httpx→katana |
| `redteam-setup` | 首次使用引导：FOFA_KEY 与 VPS 配置、通道验证、降级口径 |
| `shell-handler` | 反弹 Shell 与载荷投递：VPS 监听接收 shell，或从目标主动拉取载荷 |
| `suo5-tunnel` | suo5 经 WebShell/HTTP 建立 SOCKS5 隧道，把内网流量代理出来 |
| `unauth-exploit` | 未授权访问与信息泄露利用链：Redis/MySQL/ES/Docker/MongoDB 等暴露服务 |
| `vps-reverse-shell` | 自建 VPS 反弹 Shell 落地与中转：端口监听、非交互会话驱动、载荷投递、反向隧道 |
| `web-fingerprint` | Web 服务指纹识别：框架、中间件、CMS、组件版本 |
| `webshell-toolkit` | 冰蝎 / 哥斯拉 / 中国蚁剑的启动与用法：WebShell 管理、维持访问 |

每个技能的 `SKILL.md` 保留了来源仓库的 frontmatter
（`name` / `description` / `whenToUse` / `role` / `enabled`），
与 ARTEX 现有技能（`api-recon`、`playwright-cli`、`scopesentry`）无命名冲突。

## POC/EXP 知识库

全局共享、跨靶标复用的红队知识库（PostgreSQL 表 `poc_knowledge`），
详见 [POC-EXP知识库.md](POC-EXP知识库.md)：

- **两层一体**：自建 POC/EXP（`source != 'nuclei-template'`）与本机 nuclei
  模板库（`source = 'nuclei-template'`）同表存储，按 CVE / 组件 / 关键字一次搜两层，
  也可用 `layer=poc|nuclei` 只搜一层
- **14 归类**：rce / deserialization / file-upload / sqli / unauthorized /
  auth-bypass / weak-password / ssrf / xxe / path-traversal / info-leak /
  privesc / tunnel / other
- **三维度溯源筛选**：建立时间段（`created_at`）、来源靶标（`engagement_name`）、
  发现资产（`asset_target`）
- **Agent 工具**：`poc_kb_search`（动手前先查库）→ `poc_kb_get`（取全文）→
  `poc_kb_hit`（用后登记复用，`hit_count` 越用越准）
- **模板库导入**：`go run ./cmd/poc-kb-import --dir ~/.local/nuclei-templates`

## 来源说明

- 来源仓库：<https://github.com/Jueze-2019/dsh-redteam-mode>
  （DeepSeek Harness 红队作战指挥台插件：56 个 `redteam_*` 工具、随包技能、SQLite 事实库）
- 合并内容：`skills/`（23 个技能）与 `docs/`（知识文档）
- 未合并：`packages/`、`scripts/`、`preset/`、`redteam-proto/` 等 DSH 插件工程代码，
  它们依赖 DSH 运行时，与 ARTEX（Go 后端 + Next.js 前端）架构不兼容
- `docs/dsh-redteam/` 下为来源项目的维护档案（版本发布注记、市场 PR 记录、发版包），
  仅作归档参考，不属于 ARTEX 知识库正文
- ⚠️ 技能与文档面向**已获书面授权**的攻防演练 / 渗透测试场景，使用前请确认授权范围
