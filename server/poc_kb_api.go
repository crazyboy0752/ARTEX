package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

// POC/EXP 知识库的人工读写接口（GET 检索/详情/总览，POST 保存，DELETE 删除，
// POST hit 登记复用）。与 agent 侧 poc_kb_* 工具读写同一批 poc_knowledge 行：
// 智能体查库用工具，人在面板上看/整理用这组 API，两边数据始终一致。

// pocDTO 是一条知识库条目的 JSON 形态。列表用 compact=true（不含 content 正文），
// 详情用 compact=false。字段命名与 agent 工具的 compactPoc 对齐，前端一套类型通吃。
type pocDTO struct {
	ID           int64  `json:"id"`
	Code         string `json:"code"`
	Title        string `json:"title"`
	Kind         string `json:"kind"`
	Category     string `json:"category"`
	CategoryName string `json:"category_name"`
	Layer        string `json:"layer"`
	CVE          string `json:"cve"`
	Component    string `json:"component"`
	Versions     string `json:"versions"`
	Severity     string `json:"severity"`
	Language     string `json:"language"`
	Source       string `json:"source"`
	SourceURL    string `json:"source_url,omitempty"`
	Description  string `json:"description"`
	Usage        string `json:"usage"`
	Content      string `json:"content,omitempty"`
	Path         string `json:"path"`
	Verified     bool   `json:"verified"`
	VerifiedNote string `json:"verified_note,omitempty"`
	HitCount     int    `json:"hit_count"`
	UsedOn       string `json:"used_on,omitempty"`
	Engagement   string `json:"engagement,omitempty"`
	Asset        string `json:"asset,omitempty"`
	FoundBy      string `json:"found_by,omitempty"`
	Tags         string `json:"tags,omitempty"`
	CreatedBy    string `json:"created_by,omitempty"`
	CreatedAt    string `json:"created_at"`
	UpdatedAt    string `json:"updated_at"`
	HasContent   bool   `json:"has_content"`
	ContentBytes int64  `json:"content_bytes"`
}

func pocToDTO(p *db.PocEntry, compact bool) pocDTO {
	d := pocDTO{
		ID: p.ID, Code: p.Code, Title: p.Title, Kind: p.Kind,
		Category: p.Category, CategoryName: p.CategoryName(), Layer: p.Layer(),
		CVE: p.CVE, Component: p.Component, Versions: p.Versions,
		Severity: p.Severity, Language: p.Language, Source: p.Source,
		SourceURL: p.SourceURL, Description: p.Description, Usage: p.Usage,
		Path: p.Path, Verified: p.Verified, VerifiedNote: p.VerifiedNote,
		HitCount: p.HitCount, UsedOn: p.UsedOn,
		Engagement: p.EngagementName, Asset: p.AssetTarget,
		FoundBy: p.FoundByAgent, Tags: p.Tags, CreatedBy: p.CreatedBy,
		CreatedAt:  p.CreatedAt.Format(time.RFC3339),
		UpdatedAt:  p.UpdatedAt.Format(time.RFC3339),
		HasContent: p.HasContent, ContentBytes: p.ContentBytes,
	}
	if !compact {
		d.Content = p.Content
		// 详情不走列表查询，has_content/content_bytes 派生字段未填充，按正文现算。
		d.HasContent = p.Content != ""
		d.ContentBytes = int64(len(p.Content))
	}
	return d
}

// parsePocTime 接受 2006-01-02 或 RFC3339；空串返回零值（= 不过滤）。
func parsePocTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	if tm, err := time.Parse("2006-01-02", s); err == nil {
		return tm
	}
	if tm, err := time.Parse(time.RFC3339, s); err == nil {
		return tm
	}
	return time.Time{}
}

// pocKbList GET /api/poc-kb — 知识库检索（两层同搜，列表不带正文）。
// 参数与 db.PocFilter 同名：q/cve/component/category/kind/layer/verified_only/
// tag/engagement/asset/created_after/created_before/limit/offset。
func (s *Server) pocKbList(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	q := r.URL.Query()
	f := db.PocFilter{
		Q:         q.Get("q"),
		CVE:       q.Get("cve"),
		Component: q.Get("component"),
		Kind:      q.Get("kind"),
		Category:  q.Get("category"),
		Layer:     q.Get("layer"),
		Tag:       q.Get("tag"),
		// 来源靶标/发现资产筛选与 agent 工具同名参数对齐（engagement/asset）。
		Engagement:  q.Get("engagement"),
		AssetTarget: q.Get("asset"),
		VerifiedOnly: q.Get("verified_only") == "1" || q.Get("verified_only") == "true",
		CreatedAfter:  parsePocTime(q.Get("created_after")),
		CreatedBefore: parsePocTime(q.Get("created_before")),
		Limit:         atoiDefault(q.Get("limit"), 50),
		Offset:        atoiDefault(q.Get("offset"), 0),
	}
	if !f.CreatedBefore.IsZero() {
		// 与 agent 工具一致：止日期含当天。
		f.CreatedBefore = f.CreatedBefore.Add(24*time.Hour - time.Second)
	}
	list, err := pg.SearchPocs(r.Context(), f)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	out := make([]pocDTO, 0, len(list))
	for _, p := range list {
		out = append(out, pocToDTO(p, true))
	}
	writeJSON(w, 200, map[string]any{"pocs": out, "total": len(out)})
}

// pocKbCategories GET /api/poc-kb/categories — 14 归类全表 + 各类条数。
// 面板左侧归类导航一次拿全；0 条的归类也返回，让用户知道库里还有哪些类。
func (s *Server) pocKbCategories(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	stats, err := pg.PocCategoryStats(r.Context())
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	type catDTO struct {
		Code  string `json:"code"`
		Name  string `json:"name"`
		Hint  string `json:"hint"`
		Count int64  `json:"count"`
	}
	out := make([]catDTO, 0, len(db.PocCategories))
	for _, c := range db.PocCategories {
		out = append(out, catDTO{Code: c.Code, Name: c.Name, Hint: c.Hint, Count: stats[c.Code]})
	}
	writeJSON(w, 200, map[string]any{"categories": out})
}

// pocKbOverview GET /api/poc-kb/overview — 总览指标（总数/已验证/两层/累计复用）。
func (s *Server) pocKbOverview(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	total, verified, pocLayer, nucleiLayer, hits, err := pg.PocOverviewStats(r.Context())
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"total": total, "verified": verified, "hits": hits,
		"poc_layer": pocLayer, "nuclei_layer": nucleiLayer,
	})
}

// pocKbGet GET /api/poc-kb/{key} — 取一条完整内容（key = code 或数字 id）。
func (s *Server) pocKbGet(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	key := r.PathValue("key")
	if strings.TrimSpace(key) == "" {
		writeErr(w, 400, "key required")
		return
	}
	p, err := pg.GetPoc(r.Context(), key)
	if err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"poc": pocToDTO(p, false)})
}

// pocKbSave POST /api/poc-kb — 人工新增/更新一条（同 code 合并刷新，与 agent
// 写入路径一致）。content 留空且该 code 已有正文时不覆盖旧正文（SavePoc 语义）。
func (s *Server) pocKbSave(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var body struct {
		Code         string `json:"code"`
		Title        string `json:"title"`
		Kind         string `json:"kind"`
		Category     string `json:"category"`
		CVE          string `json:"cve"`
		Component    string `json:"component"`
		Versions     string `json:"versions"`
		Severity     string `json:"severity"`
		Language     string `json:"language"`
		Source       string `json:"source"`
		SourceURL    string `json:"source_url"`
		Description  string `json:"description"`
		Usage        string `json:"usage"`
		Content      string `json:"content"`
		Path         string `json:"path"`
		Verified     bool   `json:"verified"`
		VerifiedNote string `json:"verified_note"`
		Engagement   string `json:"engagement"`
		Asset        string `json:"asset"`
		FoundBy      string `json:"found_by"`
		Tags         string `json:"tags"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, "invalid JSON")
		return
	}
	if strings.TrimSpace(body.Title) == "" {
		writeErr(w, 400, "title 为必填项（写清是什么漏洞/组件的 POC）")
		return
	}
	p := &db.PocEntry{
		Code: body.Code, Title: body.Title, Kind: body.Kind, Category: body.Category,
		CVE: body.CVE, Component: body.Component, Versions: body.Versions,
		Severity: body.Severity, Language: body.Language, Source: body.Source,
		SourceURL: body.SourceURL, Description: body.Description, Usage: body.Usage,
		Content: body.Content, Path: body.Path, Verified: body.Verified,
		VerifiedNote: body.VerifiedNote, EngagementName: body.Engagement,
		AssetTarget: body.Asset, FoundByAgent: body.FoundBy, Tags: body.Tags,
	}
	saved, created, err := pg.SavePoc(r.Context(), p)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"poc": pocToDTO(saved, false), "created": created})
}

// pocKbDelete DELETE /api/poc-kb/{key} — 删除一条（key = code 或数字 id）。
// nuclei 模板层条目也可删（下次 poc-kb-import 会按 code 重建），不做限制。
func (s *Server) pocKbDelete(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	key := r.PathValue("key")
	n, err := pg.DeletePoc(r.Context(), key)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if n == 0 {
		writeErr(w, 404, "poc "+strconv.Quote(key)+" not found")
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": key})
}

// pocKbHit POST /api/poc-kb/{key}/hit — 登记一次复用（hit_count+1）。
// 与 agent 的 poc_kb_hit 工具同语义：人也能在面板上标记“这条我拿去打了”。
func (s *Server) pocKbHit(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	key := r.PathValue("key")
	p, err := pg.GetPoc(r.Context(), key)
	if err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	var body struct {
		UsedOn string `json:"used_on"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if err := pg.RecordPocHit(r.Context(), p.ID, strings.TrimSpace(body.UsedOn)); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "id": p.ID})
}
