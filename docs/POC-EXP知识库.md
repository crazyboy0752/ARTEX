# POC/EXP 知识库

全局共享、跨靶标复用的红队知识库：自建 POC/EXP 与本机 nuclei 模板库**两层一体**，
按 CVE / 组件 / 关键字一次搜两层。融合自 dsh-redteam-mode 的 `poc` 知识库设计，
移植到 ARTEX 的 PostgreSQL（表 `poc_knowledge`）。

> ⚠️ 仅限已获书面授权的攻防演练 / 渗透测试使用。

## 数据模型

表 `poc_knowledge`（`db/schema.sql`）。**全局表，不带 company_id / task_id**，
天然跨靶标共享。`engagement_id` / `engagement_name` / `asset_target` 只是
「来源溯源」——这条知识是在哪个靶标、哪台资产上发现/验证出来的（建立时间看
`created_at`），可按这三项筛选，不是隔离维度。

| 字段 | 说明 |
| --- | --- |
| `code` | 稳定标识（slug），智能体可直接引用；同 code 再次写入做合并刷新 |
| `title` / `kind` | 标题；形态 poc / exp / script / template / payload |
| `category` | 14 归类（见下表），内置之外一律落 `other` |
| `cve` / `component` / `versions` | CVE（多编号逗号分隔）/ 组件产品 / 影响版本 |
| `severity` / `language` | 严重程度；语言 python/go/java/bash/http/nuclei/js/php |
| `source` | web / self / manual / **nuclei-template** / kb —— `nuclei-template` 即模板库那一层 |
| `description` / `usage` / `content` | 描述 / 用法示例 / 正文（脚本/POC/原始请求） |
| `verified` / `verified_note` | 是否实测验证过 / 验证证据（哪台目标、什么回显） |
| `hit_count` / `used_on` | 被复用次数 / 最近一次用在哪个靶标 |
| `engagement_id` / `engagement_name` / `asset_target` | 来源溯源三维度 |
| `poc_search` | 全文 tsvector（标题/编号/组件/版本/标签/描述/正文），触发器自维护 |

## 14 归类

| code | 中文 | 覆盖 |
| --- | --- | --- |
| `rce` | 远程命令执行 | 框架/中间件/组件 RCE、表达式注入、模板注入 |
| `deserialization` | 反序列化 | Java/PHP/.NET 反序列化链、fastjson/jackson 等 |
| `file-upload` | 文件上传 | 上传绕过、解析漏洞、二次渲染、竞争 |
| `sqli` | SQL 注入 | 注入点验证、拖库、写文件、提权 |
| `unauthorized` | 未授权访问 | 未鉴权接口/服务（Redis、Docker、Actuator、Swagger） |
| `auth-bypass` | 认证绕过 | 登录绕过、JWT 缺陷、越权读写、逻辑缺陷 |
| `weak-password` | 弱口令 | 管理端/数据库弱口令、默认口令 |
| `ssrf` | SSRF | 服务端请求伪造、云元数据、内网探测跳板 |
| `xxe` | XXE | XML 外部实体读取与 SSRF |
| `path-traversal` | 目录穿越 | 路径穿越、任意文件读、源码/配置读取 |
| `info-leak` | 信息泄露 | 配置/凭据/源码/备份泄露 |
| `privesc` | 提权横向 | 本地提权、凭据复用、Pass-the-Hash、横向工具 |
| `tunnel` | 隧道 | suo5、frp、chisel、Neo-ReGeorg、内网代理 |
| `other` | 其它 | 不属于以上任何一类（写清用途） |

## 两层检索：一次搜两层

`db.PocFilter`（`db/poc_knowledge.go`）：

- `Q`：关键字，全文（`poc_search @@ plainto_tsquery('simple', …)`，中英文兼容）
  优先，CJK 子串自动走 `ILIKE` 兜底，覆盖标题/编号/组件/标签/描述/模板路径
- `CVE` / `Component`：编号与组件模糊查
- `Category`：逗号分隔多选，如 `rce,sqli`
- `Layer`：`all`（默认，两层）/ `poc`（只搜自建库）/ `nuclei`（只搜模板库）；
  也可用 `Source` 精确指定
- 三维度筛选：`Engagement`（靶标名模糊或靶标 id 精确）、`AssetTarget`（发现资产模糊）、
  `CreatedAfter` / `CreatedBefore`（建立时间段）
- `VerifiedOnly`、`Tag`、`Kind`、`Limit`（默认 50，上限 500）、`Offset`

排序：已验证优先 → 复用次数 → 最近更新。列表不带 `content` 正文（给
`content_bytes` / `has_content`），要全文用 `GetPoc(code)`。

## nuclei 模板库导入

```bash
go run ./cmd/poc-kb-import --dir ~/.local/nuclei-templates
```

扫描模板 YAML 的 `id` / `info.name` / `severity` / `tags` /
`classification.cve-id`，按 code=`nuclei-<模板id>` 合并刷新入库
（`kind='template'`，`language='nuclei'`，`source='nuclei-template'`），
归类先按 nuclei tags 映射、命中不到再走关键词推测。可重复执行。

数据库连接与 server 同口径：`ARTEX_PG_DSN` 环境变量优先，否则读配置文件。

## Agent 工具

worker 工具集新增（`agent/poc_kb_tools.go`）：

- `poc_kb_search`：Nday/1day 动手前的第一步，按上面全部检索维度查库
- `poc_kb_get`：按 code/id 取完整正文（脚本/POC/用法/验证证据）
- `poc_kb_hit`：实际使用后登记复用，`hit_count+1`，让“最常用”越用越准

## 相关代码

- `db/schema.sql`：`poc_knowledge` 表 + 全文触发器 + 索引
- `db/poc_knowledge.go`：归类常量、`SavePoc` / `SearchPocs` / `GetPoc` /
  `RecordPocHit` / `PocCategoryStats` / `GuessPocCategory` / `ImportNucleiTemplates`
- `db/poc_knowledge_test.go`：归类、slug 净化、检索 SQL 构建单测
- `agent/poc_kb_tools.go` + `agent/tools.go` 注册
- `cmd/poc-kb-import/main.go`：模板库导入 CLI
