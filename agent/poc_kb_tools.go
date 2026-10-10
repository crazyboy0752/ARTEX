package agent

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// POC/EXP 知识库工具：Nday/1day 动手前先查库。
// 知识库全局共享、跨靶标复用；自建 POC/EXP 与本机 nuclei 模板库同表两层，
// 按 CVE/组件/关键字一次搜两层。

// compactPoc 把检索行压成紧凑 map（列表不带 content 正文）。
func compactPoc(p *db.PocEntry) map[string]any {
	return map[string]any{
		"id": p.ID, "code": p.Code, "title": p.Title,
		"kind": p.Kind, "category": p.Category, "category_name": p.CategoryName(),
		"layer": p.Layer(), "cve": p.CVE, "component": p.Component,
		"versions": p.Versions, "severity": p.Severity, "language": p.Language,
		"verified": p.Verified, "hit_count": p.HitCount,
		"engagement": p.EngagementName, "asset": p.AssetTarget,
		"created_at":  p.CreatedAt.Format("2006-01-02"),
		"has_content": p.HasContent, "usage": p.Usage,
		"description": truncateRunes(p.Description, 200),
	}
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

func (t *ToolSet) pocKBSearch() actool.CoreTool {
	return t.readExpTool("poc_kb_search",
		"查 POC/EXP 知识库（Nday/1day 动手前的第一步）：按 CVE/组件/关键字一次搜两层——自建 POC/EXP 库 + 本机 nuclei 模板库（source=nuclei-template）。14 归类：rce/deserialization/file-upload/sqli/unauthorized/auth-bypass/weak-password/ssrf/xxe/path-traversal/info-leak/privesc/tunnel/other。支持按建立时间段、来源靶标、发现资产筛选。返回 code，用 poc_kb_get 取全文；实际使用后调 poc_kb_hit 登记复用。",
		obj(map[string]any{
			"q":              str("关键字：CVE 编号/组件名/漏洞名，如 CVE-2021-44228、Shiro、log4j；省略=不按关键字过滤"),
			"cve":            str("CVE 精确/模糊，如 CVE-2021-44228；省略=不过滤"),
			"component":      str("组件/产品模糊，如 weblogic、泛微；省略=不过滤"),
			"category":       str("归类，逗号分隔多个，如 rce,sqli；省略=全部分类"),
			"layer":          str("搜哪层：all(默认，两层)/poc(只搜自建库)/nuclei(只搜模板库)"),
			"engagement":     str("来源靶标筛选（靶标名模糊或靶标 id 精确）；省略=跨全部靶标"),
			"asset":          str("发现资产筛选（IP/域名模糊）；省略=不过滤"),
			"created_after":  str("建立时间起（含），如 2026-01-01；省略=不限"),
			"created_before": str("建立时间止（含），如 2026-06-30；省略=不限"),
			"verified_only":  map[string]any{"type": "boolean", "description": "只看已实测验证过的；默认 false"},
			"limit":          intp("返回条数，默认 50，上限 500"),
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Q             string `json:"q"`
				CVE           string `json:"cve"`
				Component     string `json:"component"`
				Category      string `json:"category"`
				Layer         string `json:"layer"`
				Engagement    string `json:"engagement"`
				Asset         string `json:"asset"`
				CreatedAfter  string `json:"created_after"`
				CreatedBefore string `json:"created_before"`
				VerifiedOnly  bool   `json:"verified_only"`
				Limit         int    `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)
			f := db.PocFilter{
				Q: a.Q, CVE: a.CVE, Component: a.Component, Category: a.Category,
				Layer: a.Layer, VerifiedOnly: a.VerifiedOnly,
				Engagement: a.Engagement, AssetTarget: a.Asset, Limit: a.Limit,
			}
			if s := strings.TrimSpace(a.CreatedAfter); s != "" {
				if tm, err := time.Parse("2006-01-02", s); err == nil {
					f.CreatedAfter = tm
				}
			}
			if s := strings.TrimSpace(a.CreatedBefore); s != "" {
				if tm, err := time.Parse("2006-01-02", s); err == nil {
					// 止日期含当天 23:59:59
					f.CreatedBefore = tm.Add(24*time.Hour - time.Second)
				}
			}
			list, err := t.ts.DBOf().SearchPocs(ctx, f)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			out := make([]map[string]any, 0, len(list))
			for _, p := range list {
				out = append(out, compactPoc(p))
			}
			return jsonResult(map[string]any{"pocs": out, "total": len(out)})
		})
}

func (t *ToolSet) pocKBGet() actool.CoreTool {
	return t.readExpTool("poc_kb_get",
		"取一条 POC/EXP 的完整内容（正文/脚本/用法/验证证据全量返回，直接拿去用）。key 传 poc_kb_search 返回的 code 或数字 id。",
		obj(map[string]any{
			"key": str("知识库 code（如 nuclei-CVE-2021-44228）或数字 id"),
		}, "key"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Key string `json:"key"`
			}
			_ = json.Unmarshal(in, &a)
			p, err := t.ts.DBOf().GetPoc(ctx, a.Key)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			m := compactPoc(p)
			m["content"] = p.Content
			m["source_url"] = p.SourceURL
			m["verified_note"] = p.VerifiedNote
			m["used_on"] = p.UsedOn
			m["found_by"] = p.FoundByAgent
			m["tags"] = p.Tags
			return jsonResult(m)
		})
}

func (t *ToolSet) pocKBHit() actool.CoreTool {
	return t.readExpTool("poc_kb_hit",
		"登记一次知识库复用：某条 POC/EXP 被实际拿去打了之后调用，hit_count+1 并记录用在哪个靶标/目标，让“最常用”排序越用越准。id 传 poc_kb_search 返回的 id。",
		obj(map[string]any{
			"id":      intp("知识库条目 id"),
			"used_on": str("用在哪个靶标/目标，如 “某集团-10.0.0.1”"),
		}, "id"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				ID     int64  `json:"id"`
				UsedOn string `json:"used_on"`
			}
			_ = json.Unmarshal(in, &a)
			if a.ID <= 0 {
				return actool.Errorf("id required"), nil
			}
			if err := t.ts.DBOf().RecordPocHit(ctx, a.ID, a.UsedOn); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{"ok": true, "id": a.ID})
		})
}

// pocKBSave 把验证过的 POC/EXP 存回知识库自建层：打完靶沉淀资产，
// 后续任务动手前 poc_kb_search 先查库直接用，不重复造轮子。
// 同 code 再存=覆盖刷新（SavePoc 语义）。溯源自动带：engagement=当前任务，
// found_by=本 agent 名；asset 由调用方按发现填。
func (t *ToolSet) pocKBSave() actool.CoreTool {
	return t.writeExpTool("poc_kb_save",
		"保存一条 POC/EXP 到知识库（自建层，全局共享、跨靶标复用）：验证过的漏洞把 payload/脚本/请求存回来，后续任务动手前先查库直接用。同 code 再存=覆盖刷新。verified=true 表示已实测跑通，配 verified_note 写清在哪台目标、什么回显。存完配合 poc_kb_hit 登记本次复用。",
		obj(map[string]any{
			"title":       str("漏洞/组件标题，如：泛微 OA 前台 SQL 注入（ecoffice）"),
			"code":        str("稳定标识 slug；留空按标题+CVE 自动生成；同 code 覆盖刷新"),
			"kind":        str("poc|exp|script|payload，默认 poc"),
			"category":    str("14 归类：rce/deserialization/file-upload/sqli/unauthorized/auth-bypass/weak-password/ssrf/xxe/path-traversal/info-leak/privesc/tunnel/other；留空按内容关键词推测"),
			"cve":         str("CVE/编号，如 CVE-2023-22518"),
			"component":   str("组件/产品，如 泛微OA、Weblogic"),
			"versions":    str("受影响版本"),
			"severity":    str("critical|high|medium|low|info"),
			"language":    str("python|bash|http|java|go…"),
			"description": str("漏洞成因与影响（简述）"),
			"usage":       str("用法/命令行示例，如 nuclei -t tpl.yaml -u <目标> 或手工请求"),
			"content":     str("正文：完整 payload/脚本/原始请求报文（存成可直接复用的形态）"),
			"tags":        str("标签，逗号分隔"),
			"verified":    map[string]any{"type": "boolean", "description": "是否已实测跑通；true 时请填 verified_note"},
			"verified_note": str("验证证据：在哪台目标、什么回显/时间"),
			"asset":       str("发现/验证该 POC 的资产（IP/域名），溯源用；可省略"),
		}, "title"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Code, Title, Kind, Category, CVE, Component, Versions, Severity, Language string
				Description, Usage, Content, Tags, VerifiedNote, Asset                   string
				Verified                                                                  bool
			}
			_ = json.Unmarshal(in, &a)
			if strings.TrimSpace(a.Title) == "" {
				return actool.Errorf("title required：写清是什么漏洞/组件的 POC"), nil
			}
			// 留空的 category 按内容关键词推测（比落 other 有用，与 nuclei 导入同口径）。
			cat := strings.TrimSpace(a.Category)
			if cat == "" {
				cat = db.GuessPocCategory(a.Title + " " + a.CVE + " " + a.Description + " " + a.Content)
			}
			// 溯源：任务 id 自动带（本条知识来自哪次任务），found_by=本 agent。
			engagement := ""
			if ri := RunInfoFrom(ctx); ri.TaskID > 0 {
				engagement = strconv.FormatInt(ri.TaskID, 10)
			} else if t.taskID > 0 {
				engagement = strconv.FormatInt(t.taskID, 10)
			}
			p := &db.PocEntry{
				Code: strings.TrimSpace(a.Code), Title: strings.TrimSpace(a.Title),
				Kind: strings.TrimSpace(a.Kind), Category: cat,
				CVE: strings.TrimSpace(a.CVE), Component: strings.TrimSpace(a.Component),
				Versions: strings.TrimSpace(a.Versions),
				Severity: strings.ToLower(strings.TrimSpace(a.Severity)),
				Language: strings.TrimSpace(a.Language), Source: db.PocSourceSelf,
				Description: a.Description, Usage: a.Usage, Content: a.Content,
				Verified: a.Verified, VerifiedNote: strings.TrimSpace(a.VerifiedNote),
				EngagementID: engagement, AssetTarget: strings.TrimSpace(a.Asset),
				FoundByAgent: t.worker, Tags: strings.TrimSpace(a.Tags),
			}
			saved, created, err := t.ts.DBOf().SavePoc(ctx, p)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{
				"ok": true, "id": saved.ID, "code": saved.Code,
				"created": created, "category": saved.Category,
			})
		})
}
