---
name: fofa-recon
description: 用 FOFA（fafaapi.info 中转）批量测绘靶标资产（域名/IP/端口/标题/指纹）；内置限速客户端随技能分发，单线程 + 最小间隔 + 结果缓存，按日额度内保守使用
whenToUse: 信息收集阶段需要快速铺开某单位/域名的互联网资产面时
role: recon
enabled: true
---

# FOFA 资产测绘（中转限速版）

## 凭据与接口
- API Key：环境变量 `FOFA_KEY`（ARTEX「系统配置 → 红队环境变量」注入所有 agent bash；当前配的即**中转 key**。**任何 key 都不要写进仓库**）
- 接口：`GET https://fafaapi.info/fofaapi`（中转，非 FOFA 官方直连）
- 参数：`key`、`queryStr`（查询语句的 base64）、`size`、`page`、`fields`、`route`、`full`
- 额度：中转按**日额度**计，响应字段 `newTodayRemaining` 为当日剩余——客户端每页把 `remain=` 打到 stderr，**盯着它，归零当天就停**，改用证书透明 / DNS / 搜索引擎，不要死磕。

## 客户端（脚本随技能分发，不要手写 curl 循环）

`scripts/fofa_relay.py`：单线程 + 最小间隔（默认 3.5s，中转实测限速 3s 必须留余量）+ 结果缓存（同查询只拉一次）+ 逐页去重。

```bash
mkdir -p runs
python3 scripts/fofa_relay.py 'domain="example.com"' --pages 2 --size 100 --interval 3.5
python3 scripts/fofa_relay.py 'cert="example.com"' --pages 3
python3 scripts/fofa_relay.py 'org="示例科技有限公司"' --pages 2
python3 scripts/fofa_relay.py 'ip="203.0.113.0/24" && port="3306"' --pages 1
```

- **输出**：`runs/fofa-<md5(query)前8位>.jsonl`，每行一个资产 `{host,ip,port,title,domain,server,protocol,country,asn}`
- **缓存**：同查询再次执行直接命中返回（stderr 打 `[cache]`）——**要重新拉取先删缓存文件**
- **额度自检**：每页 stderr 打 `rows/total/remain`；开跑先看一眼 `remain`，`remain=0` 直接停
- **错误即停**：客户端收到 `error/errmsg` 立即停止不重试（限速/额度类错误死磕只会更糟），按 errmsg 排查后换更精确的查询
- `--interval` 别调到 **3 以下**（中转 3 秒限速，低于必 429）；`--size` 别超过 100

### key 有效性验证（最小消耗：1 次额度）
```bash
python3 scripts/fofa_relay.py 'domain="example.com"' --pages 1 --size 10 --out runs/fofa-selftest.jsonl
```
stderr 出现 `[page 1] … remain=N` 即 key 可用；出现 `[stop] … errmsg` 按错误信息排查（key 错 / 额度尽 / 限速）。

## 使用纪律（重要）
1. **精确查询优先**：`domain=` / `cert=` / `org=` 先缩小范围，再考虑 `body=` / `title=` 等宽泛语句。宽语句返回几十万条没意义，还烧额度。
2. **不要全量翻页**：默认只取前 1–3 页（每页 100 条）拿到测绘入口即可。
3. **单进程单线程**：同一时刻只跑一个采集任务；多个查询串行排队。
4. **结果落盘缓存**：同一查询不要重复拉，先看 `runs/fofa-*.jsonl` 是否已有（客户端也会自动命中）。
5. **长任务放后台**：用 `run_in_background` 跑，别阻塞对话。
6. **额度归零或被限速时**改用其他数据源（证书透明、DNS、搜索引擎），不要死磕。

## 落库（ARTEX 资产图）

读 `runs/fofa-*.jsonl` 逐条调 `insert_assets`（按工具 schema 填，缺的字段别编造）：

```json
{
  "assets": [
    {"type": "service", "ip": "203.0.113.10", "port": 443, "url": "https://a.example.com:443", "page_title": "登录", "service_name": "nginx"},
    {"type": "subdomain", "domain": "a.example.com", "record_type": "A", "record_value": ["203.0.113.10"]},
    {"type": "ip", "ip": "203.0.113.10", "open_ports": [80, 443], "bound_domains": ["a.example.com"]}
  ]
}
```

- HTTP 资产带 `url`（含协议与端口，`service_type` 自动设为 http）；非 HTTP 服务带 `port` + `service_name`
- 域名走 `subdomain` 类型填 `domain`；`title` → `page_title`、`server` → `technologies`/`service_name` 按实填
- 落库前对 `ip` 类型查重（本任务已有同 IP 就只补 `open_ports`/`bound_domains`），避免重复行

## 常用查询语句
| 目的 | 语句 |
|---|---|
| 某域名全部资产 | `domain="example.com"` |
| 证书包含该域名 | `cert="example.com"` |
| 某 C 段 | `ip="203.0.113.0/24"` |
| 单位名称 | `org="示例科技有限公司"` |
| 按标题找后台 | `title="登录" && domain="example.com"` |
| 按 body 特征 | `body="/seeyon/"` |
| 指定端口 | `ip="203.0.113.0/24" && port="3306"` |

> 宽泛语句（单独用 `body=` / `title=`）结果量大、消耗额度快，务必叠加域名或 IP 限定。
