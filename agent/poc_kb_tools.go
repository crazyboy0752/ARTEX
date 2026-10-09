package agent

import (
	"context"
	"encoding/json"
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
