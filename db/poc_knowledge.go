package db

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"

	"gopkg.in/yaml.v3"
)

// =====================================================================
// POC/EXP 知识库（全局共享、跨靶标复用）
//
// 融合自 dsh-redteam-mode 的 poc 知识库设计，移植到 PostgreSQL。
// 全局表 poc_knowledge 不带 company_id / task_id，天然跨靶标共享；
// engagement_id/name 与 asset_target 只是「来源溯源」维度（这条知识在
// 哪个靶标、哪台资产上发现/验证），可按它们筛选，不是隔离维度。
//
// 两层一体：自建 POC/EXP（source != 'nuclei-template'）与本机 nuclei
// 模板库（source = 'nuclei-template', kind = 'template',
// language = 'nuclei'）同表存储，按 CVE/组件/关键字一次搜两层。
// =====================================================================

// PocCategory 是知识库 14 归类之一。
type PocCategory struct {
	Code string // 归类 code，落库值
	Name string // 中文名
	Hint string // 给智能体/用户的归类提示
}

// PocCategories 是 14 归类全表（顺序即展示顺序）。
var PocCategories = []PocCategory{
	{Code: "rce", Name: "远程命令执行", Hint: "框架/中间件/组件 RCE、表达式注入、模板注入"},
	{Code: "deserialization", Name: "反序列化", Hint: "Java/PHP/.NET 反序列化链、fastjson/jackson 等"},
	{Code: "file-upload", Name: "文件上传", Hint: "上传绕过、解析漏洞、二次渲染、竞争"},
	{Code: "sqli", Name: "SQL 注入", Hint: "注入点验证、拖库、写文件、提权"},
	{Code: "unauthorized", Name: "未授权访问", Hint: "未鉴权接口/服务（Redis、Docker、Actuator、Swagger）"},
	{Code: "auth-bypass", Name: "认证绕过", Hint: "登录绕过、JWT 缺陷、越权读写、逻辑缺陷"},
	{Code: "weak-password", Name: "弱口令", Hint: "管理端弱口令、数据库弱口令、默认口令"},
	{Code: "ssrf", Name: "SSRF", Hint: "服务端请求伪造、云元数据、内网探测跳板"},
	{Code: "xxe", Name: "XXE", Hint: "XML 外部实体读取与 SSRF"},
	{Code: "path-traversal", Name: "目录穿越", Hint: "路径穿越、任意文件读、源码/配置读取"},
	{Code: "info-leak", Name: "信息泄露", Hint: "配置/凭据/源码/备份泄露"},
	{Code: "privesc", Name: "提权横向", Hint: "本地提权、凭据复用、Pass-the-Hash、横向工具"},
	{Code: "tunnel", Name: "隧道", Hint: "suo5、frp、chisel、Neo-ReGeorg、内网代理"},
	{Code: "other", Name: "其它", Hint: "不属于上面任何一类（写清用途）"},
}

// PocCategoryName 把归类 code 转成中文名，未知值原样返回。
func PocCategoryName(code string) string {
	for _, c := range PocCategories {
		if c.Code == code {
			return c.Name
		}
	}
	if code == "" {
		return "未归类"
	}
	return code
}

// normalizePocCategory 白名单归类：内置 14 类之外一律落 other，
// 避免面板出现一堆拼写变体。
func normalizePocCategory(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "other"
	}
	for _, c := range PocCategories {
		if c.Code == raw {
			return raw
		}
	}
	return "other"
}

// POC 内容形态。
const (
	PocKindPoc      = "poc"
	PocKindExp      = "exp"
	PocKindScript   = "script"
	PocKindTemplate = "template"
	PocKindPayload  = "payload"
)

// POC 来源；nuclei-template 即「模板库那一层」。
const (
	PocSourceWeb            = "web"
	PocSourceSelf           = "self"
	PocSourceManual         = "manual"
	PocSourceNucleiTemplate = "nuclei-template"
	PocSourceKB             = "kb"
)

// 检索分层快捷值。
const (
	PocLayerAll    = "all"    // 两层都搜（默认）
	PocLayerPOC    = "poc"    // 只搜自建 POC/EXP 库
	PocLayerNuclei = "nuclei" // 只搜 nuclei 模板库
)

func normalizePocKind(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case PocKindExp:
		return PocKindExp
	case PocKindScript:
		return PocKindScript
	case PocKindTemplate:
		return PocKindTemplate
	case PocKindPayload:
		return PocKindPayload
	default:
		return PocKindPoc
	}
}

func normalizePocSource(raw string) string {
	switch strings.TrimSpace(raw) {
	case PocSourceWeb, PocSourceManual, PocSourceNucleiTemplate, PocSourceKB:
		return strings.TrimSpace(raw)
	default:
		return PocSourceSelf
	}
}

// PocEntry 是 poc_knowledge 的一行。
type PocEntry struct {
	ID             int64
	Code           string // 稳定标识（slug），智能体可直接引用
	Title          string
	Kind           string // poc | exp | script | template | payload
	Category       string // 14 归类 code
	CVE            string
	Component      string
	Versions       string
	Severity       string
	Language       string
	Source         string // web | self | manual | nuclei-template | kb
	SourceURL      string
	Description    string
	Usage          string
	Content        string
	Path           string
	Verified       bool
	VerifiedNote   string
	HitCount       int
	UsedOn         string
	EngagementID   string // 来源靶标 id（溯源）
	EngagementName string // 来源靶标名（溯源）
	AssetTarget    string // 发现资产（溯源）
	FoundByAgent   string
	Tags           string
	CreatedBy      string
	CreatedAt      time.Time
	UpdatedAt      time.Time
	// 列表检索时的派生字段（GetPoc 不填充）
	ContentBytes int64
	HasContent   bool
}

// CategoryName 返回中文归类名。
func (p *PocEntry) CategoryName() string { return PocCategoryName(p.Category) }

// Layer 返回条目所在层：nuclei 模板层 / 自建 POC 层。
func (p *PocEntry) Layer() string {
	if p.Source == PocSourceNucleiTemplate {
		return PocLayerNuclei
	}
	return PocLayerPOC
}

// slugPocCode 净化 code（会被当成目录名）：只保留字母/数字/中文/_/./-，
// 其余换成 -，并去掉开头的 ./-。与 dsh-redteam-mode 的 slugPoc 同规则，
// 防止 code='../../escaped' 把正文写到库目录之外。
func slugPocCode(raw string) string {
	var b strings.Builder
	for _, r := range raw {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '_', r == '.', r == '-', unicode.Is(unicode.Han, r):
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	return strings.TrimLeft(b.String(), ".-")
}

// makePocCode code 为空时按标题+CVE 生成 slug。
func makePocCode(title, cve, code string) (string, error) {
	raw := strings.TrimSpace(code)
	if raw == "" {
		base := strings.TrimSpace(title)
		if cve = strings.TrimSpace(cve); cve != "" {
			base = cve + "-" + base
		}
		// 取前 40 个 rune，避免超长文件名
		r := []rune(base)
		if len(r) > 40 {
			r = r[:40]
		}
		raw = string(r)
	}
	slug := slugPocCode(raw)
	if slug == "" {
		return "", fmt.Errorf("poc.code invalid（净化后为空，请用字母/数字/中文/短横线）")
	}
	return slug, nil
}

// GuessPocCategory 按关键词推测归类（nuclei 模板导入、老条目补标用；
// 新写入条目以调用方传入的 category 为准）。顺序即优先级。
func GuessPocCategory(text string) string {
	t := strings.ToLower(text)
	has := func(words ...string) bool {
		for _, w := range words {
			if strings.Contains(t, w) {
				return true
			}
		}
		return false
	}
	if has("反序列化", "deserial", "shiro", "fastjson", "weblogic", "log4j", "jackson") {
		return "deserialization"
	}
	if has("文件上传", "file-upload", "fileupload", "upload", "getshell", "webshell", "写马") {
		return "file-upload"
	}
	if has("sql 注入", "sqli", "sql注入", "注入拖库", "union select") {
		return "sqli"
	}
	if has("弱口令", "爆破", "brute", "默认口令", "默认凭据", "hydra", "default-login", "default login") {
		return "weak-password"
	}
	if has("隧道", "socks", "suo5", "frp", "chisel", "regeorg", "代理") {
		return "tunnel"
	}
	if has("未授权", "unauth", "免认证", "免鉴权", "未鉴权", "无鉴权") {
		return "unauthorized"
	}
	if has("越权", "认证绕过", "鉴权绕过", "jwt", "逻辑漏洞", "验证码绕过", "auth-bypass", "auth bypass") {
		return "auth-bypass"
	}
	if has("rce", "命令执行", "代码执行", "表达式注入", "模板注入", "ssti", "命令注入", "远程执行") {
		return "rce"
	}
	if has("ssrf", "服务端请求伪造") {
		return "ssrf"
	}
	if has("xxe", "外部实体") {
		return "xxe"
	}
	if has("任意文件读", "文件读取", "目录穿越", "路径穿越", "path traversal", "lfi", "rfi", "任意文件下载") {
		return "path-traversal"
	}
	if has("提权", "横向", "pass-the-hash", "mimikatz", "impacket", "凭据复用", "privesc", "privilege") {
		return "privesc"
	}
	if has("信息泄露", "配置泄露", "敏感信息", "源码泄露", "泄露", "leak", "disclosure", "exposure") {
		return "info-leak"
	}
	return "other"
}

// likeEscape 转义 LIKE 通配符。
func likeEscape(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

// PocFilter 是 SearchPocs 的检索条件。
type PocFilter struct {
	Q             string // 关键字：全文（标题/编号/组件/版本/标签/描述/正文）+ LIKE 兜底
	CVE           string
	Component     string
	Kind          string // 精确
	Category      string // 逗号分隔支持多个，如 "rce,sqli"
	Source        string // 精确 source；与 Layer 二选一
	Layer         string // all | poc | nuclei（默认 all）
	VerifiedOnly  bool
	Tag           string
	Engagement    string    // 来源靶标：engagement_id 精确或 engagement_name 模糊
	AssetTarget   string    // 发现资产：模糊
	CreatedAfter  time.Time // 建立时间起（含）
	CreatedBefore time.Time // 建立时间止（含）
	Limit         int       // 默认 50，上限 500
	Offset        int
}

// buildPocSearchQuery 把 PocFilter 编译成 SQL + 参数（纯函数，可单测）。
func buildPocSearchQuery(f PocFilter) (string, []any) {
	where := []string{}
	args := []any{}
	add := func(cond string, v ...any) {
		where = append(where, cond)
		args = append(args, v...)
	}
	ph := func() string { return fmt.Sprintf("$%d", len(args)+1) }

	if q := strings.TrimSpace(f.Q); q != "" {
		// 全文优先（simple 词典兼容中英文），CJK 子串走 LIKE 兜底
		like := "%" + likeEscape(q) + "%"
		conds := []string{fmt.Sprintf(`poc_search @@ plainto_tsquery('simple', %s)`, ph())}
		args = append(args, q)
		for _, col := range []string{"title", "cve", "component", "tags", "description", "path"} {
			conds = append(conds, fmt.Sprintf(`%s ILIKE %s ESCAPE '\'`, col, ph()))
			args = append(args, like)
		}
		where = append(where, "("+strings.Join(conds, " OR ")+")")
	}
	if v := strings.TrimSpace(f.CVE); v != "" {
		add(`cve ILIKE `+ph()+` ESCAPE '\'`, "%"+likeEscape(v)+"%")
	}
	if v := strings.TrimSpace(f.Component); v != "" {
		add(`component ILIKE `+ph()+` ESCAPE '\'`, "%"+likeEscape(v)+"%")
	}
	if v := strings.TrimSpace(f.Kind); v != "" {
		add(`kind = `+ph(), normalizePocKind(v))
	}
	if v := strings.TrimSpace(f.Category); v != "" {
		list := []string{}
		for _, c := range strings.Split(v, ",") {
			if c = normalizePocCategory(c); c != "" {
				list = append(list, c)
			}
		}
		if len(list) == 1 {
			add(`category = `+ph(), list[0])
		} else if len(list) > 1 {
			holders := make([]string, len(list))
			for i := range list {
				holders[i] = ph()
				args = append(args, list[i])
			}
			where = append(where, `category IN (`+strings.Join(holders, ", ")+`)`)
		}
	}
	// 分层：Layer 快捷值优先于 Source 精确值
	switch strings.TrimSpace(f.Layer) {
	case PocLayerNuclei:
		add(`source = `+ph(), PocSourceNucleiTemplate)
	case PocLayerPOC:
		add(`source <> `+ph(), PocSourceNucleiTemplate)
	default:
		if v := strings.TrimSpace(f.Source); v != "" {
			add(`source = `+ph(), normalizePocSource(v))
		}
	}
	if f.VerifiedOnly {
		where = append(where, `verified = TRUE`)
	}
	if v := strings.TrimSpace(f.Tag); v != "" {
		add(`tags ILIKE `+ph()+` ESCAPE '\'`, "%"+likeEscape(v)+"%")
	}
	// 来源溯源三维度筛选
	if v := strings.TrimSpace(f.Engagement); v != "" {
		pID := ph()
		args = append(args, v)
		pName := ph()
		args = append(args, "%"+likeEscape(v)+"%")
		where = append(where, `(engagement_id = `+pID+` OR engagement_name ILIKE `+pName+` ESCAPE '\')`)
	}
	if v := strings.TrimSpace(f.AssetTarget); v != "" {
		add(`asset_target ILIKE `+ph()+` ESCAPE '\'`, "%"+likeEscape(v)+"%")
	}
	if !f.CreatedAfter.IsZero() {
		add(`created_at >= `+ph(), f.CreatedAfter)
	}
	if !f.CreatedBefore.IsZero() {
		add(`created_at <= `+ph(), f.CreatedBefore)
	}
	clause := ""
	if len(where) > 0 {
		clause = "WHERE " + strings.Join(where, " AND ")
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	// 注意：ph() 只按当前 len(args) 算占位符，不推进 args；
	// 连续两个 ph() 会给出相同编号，必须逐个先 append 再取下一个。
	pLimit := ph()
	args = append(args, limit)
	pOffset := ph()
	args = append(args, f.Offset)
	query := fmt.Sprintf(`SELECT id, code, title, kind, category, cve, component, versions, severity,
		language, source, source_url, description, usage, path, verified, verified_note,
		hit_count, used_on, engagement_id, engagement_name, asset_target, found_by_agent,
		tags, created_by, created_at, updated_at,
		length(content) AS content_bytes,
		CASE WHEN content = '' THEN FALSE ELSE TRUE END AS has_content
		FROM poc_knowledge %s
		ORDER BY verified DESC, hit_count DESC, updated_at DESC, id DESC
		LIMIT %s OFFSET %s`, clause, pLimit, pOffset)
	return query, args
}

// scanPocRow 把列表行扫进 PocEntry（content 本体不进列表）。
func scanPocRow(scan func(...any) error) (*PocEntry, error) {
	p := &PocEntry{}
	err := scan(&p.ID, &p.Code, &p.Title, &p.Kind, &p.Category, &p.CVE, &p.Component,
		&p.Versions, &p.Severity, &p.Language, &p.Source, &p.SourceURL, &p.Description,
		&p.Usage, &p.Path, &p.Verified, &p.VerifiedNote, &p.HitCount, &p.UsedOn,
		&p.EngagementID, &p.EngagementName, &p.AssetTarget, &p.FoundByAgent,
		&p.Tags, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt, &p.ContentBytes, &p.HasContent)
	return p, err
}

// SearchPocs 检索知识库：Nday/1day 动手前的第一步。
// 按 CVE/组件/关键字一次搜两层（自建库 + nuclei 模板库），并支持 14 归类、
// 建立时间段、来源靶标、发现资产三维度筛选。列表不带 content 正文，
// 要全文用 GetPoc(code)。
func (d *DB) SearchPocs(ctx context.Context, f PocFilter) ([]*PocEntry, error) {
	query, args := buildPocSearchQuery(f)
	rows, err := d.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*PocEntry{}
	for rows.Next() {
		p, err := scanPocRow(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// SavePoc 落库一份通用 POC/EXP。同 code 会合并刷新（便于"同一漏洞的新版
// 本 POC"覆盖旧版），不存在则新建。返回条目与是否为新建。
func (d *DB) SavePoc(ctx context.Context, p *PocEntry) (*PocEntry, bool, error) {
	title := strings.TrimSpace(p.Title)
	if title == "" {
		return nil, false, fmt.Errorf("poc.title required（写清是什么漏洞/组件的 POC）")
	}
	code, err := makePocCode(title, p.CVE, p.Code)
	if err != nil {
		return nil, false, err
	}
	now := time.Now()
	var id int64
	var created bool
	err = d.QueryRowContext(ctx, `INSERT INTO poc_knowledge(
			code, title, kind, category, cve, component, versions, severity, language,
			source, source_url, description, usage, content, path, verified, verified_note,
			engagement_id, engagement_name, asset_target, found_by_agent, tags,
			created_by, created_at, updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$24)
		ON CONFLICT(code) DO UPDATE SET
			title = excluded.title, kind = excluded.kind, category = excluded.category,
			cve = COALESCE(NULLIF(excluded.cve, ''), poc_knowledge.cve),
			component = COALESCE(NULLIF(excluded.component, ''), poc_knowledge.component),
			versions = COALESCE(NULLIF(excluded.versions, ''), poc_knowledge.versions),
			severity = COALESCE(NULLIF(excluded.severity, ''), poc_knowledge.severity),
			language = COALESCE(NULLIF(excluded.language, ''), poc_knowledge.language),
			source = excluded.source,
			source_url = COALESCE(NULLIF(excluded.source_url, ''), poc_knowledge.source_url),
			description = COALESCE(NULLIF(excluded.description, ''), poc_knowledge.description),
			usage = COALESCE(NULLIF(excluded.usage, ''), poc_knowledge.usage),
			content = CASE WHEN excluded.content <> '' THEN excluded.content ELSE poc_knowledge.content END,
			path = COALESCE(NULLIF(excluded.path, ''), poc_knowledge.path),
			verified = excluded.verified,
			verified_note = COALESCE(NULLIF(excluded.verified_note, ''), poc_knowledge.verified_note),
			engagement_id = COALESCE(NULLIF(excluded.engagement_id, ''), poc_knowledge.engagement_id),
			engagement_name = COALESCE(NULLIF(excluded.engagement_name, ''), poc_knowledge.engagement_name),
			asset_target = COALESCE(NULLIF(excluded.asset_target, ''), poc_knowledge.asset_target),
			found_by_agent = COALESCE(NULLIF(excluded.found_by_agent, ''), poc_knowledge.found_by_agent),
			tags = COALESCE(NULLIF(excluded.tags, ''), poc_knowledge.tags),
			created_by = COALESCE(NULLIF(excluded.created_by, ''), poc_knowledge.created_by),
			updated_at = now()
		RETURNING id, (xmax = 0)`,
		code, title, normalizePocKind(p.Kind), normalizePocCategory(p.Category),
		strings.TrimSpace(p.CVE), strings.TrimSpace(p.Component), strings.TrimSpace(p.Versions),
		strings.TrimSpace(p.Severity), strings.TrimSpace(p.Language),
		normalizePocSource(p.Source), strings.TrimSpace(p.SourceURL),
		p.Description, p.Usage, p.Content, strings.TrimSpace(p.Path),
		p.Verified, strings.TrimSpace(p.VerifiedNote),
		strings.TrimSpace(p.EngagementID), strings.TrimSpace(p.EngagementName),
		strings.TrimSpace(p.AssetTarget), strings.TrimSpace(p.FoundByAgent),
		strings.TrimSpace(p.Tags), strings.TrimSpace(p.CreatedBy), now,
	).Scan(&id, &created)
	if err != nil {
		return nil, false, err
	}
	got, err := d.GetPoc(ctx, code)
	if err != nil {
		return nil, false, err
	}
	return got, created, nil
}

// GetPoc 取一条 POC 的完整内容（智能体要直接拿去用，所以连正文一起给）。
// key 可以是 code 或数字 id。
func (d *DB) GetPoc(ctx context.Context, key string) (*PocEntry, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return nil, fmt.Errorf("poc key required")
	}
	var row *sql.Row
	if isDigits(key) {
		row = d.QueryRowContext(ctx, `SELECT id, code, title, kind, category, cve, component,
			versions, severity, language, source, source_url, description, usage, content, path,
			verified, verified_note, hit_count, used_on, engagement_id, engagement_name,
			asset_target, found_by_agent, tags, created_by, created_at, updated_at
			FROM poc_knowledge WHERE id = $1`, key)
	} else {
		row = d.QueryRowContext(ctx, `SELECT id, code, title, kind, category, cve, component,
			versions, severity, language, source, source_url, description, usage, content, path,
			verified, verified_note, hit_count, used_on, engagement_id, engagement_name,
			asset_target, found_by_agent, tags, created_by, created_at, updated_at
			FROM poc_knowledge WHERE code = $1`, key)
	}
	p := &PocEntry{}
	err := row.Scan(&p.ID, &p.Code, &p.Title, &p.Kind, &p.Category, &p.CVE, &p.Component,
		&p.Versions, &p.Severity, &p.Language, &p.Source, &p.SourceURL, &p.Description,
		&p.Usage, &p.Content, &p.Path, &p.Verified, &p.VerifiedNote, &p.HitCount, &p.UsedOn,
		&p.EngagementID, &p.EngagementName, &p.AssetTarget, &p.FoundByAgent,
		&p.Tags, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("poc %q not found", key)
	}
	return p, err
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// RecordPocHit 登记一次复用：hit_count +1，并记录用在哪个靶标/目标。
// 智能体每次从知识库取走 POC 实际使用后都应调用，好让"最常用"排前面。
func (d *DB) RecordPocHit(ctx context.Context, id int64, usedOn string) error {
	_, err := d.ExecContext(ctx, `UPDATE poc_knowledge
		SET hit_count = hit_count + 1, used_on = $2, updated_at = now() WHERE id = $1`, id, usedOn)
	return err
}

// PocCategoryStats 按 14 归类统计条数（面板分组展示用）。
func (d *DB) PocCategoryStats(ctx context.Context) (map[string]int64, error) {
	rows, err := d.QueryContext(ctx, `SELECT category, COUNT(*) FROM poc_knowledge GROUP BY category`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var c string
		var n int64
		if err := rows.Scan(&c, &n); err != nil {
			return nil, err
		}
		out[c] = n
	}
	return out, rows.Err()
}

// DBOf 暴露底层 *DB，给全局（非 exploration 作用域）存储用，
// 比如 poc_knowledge。ExplorationStore 的方法保持作用域语义不变。
func (s *ExplorationStore) DBOf() *DB { return s.db }

// =====================================================================
// 本机 nuclei 模板库导入
// =====================================================================

var cvePattern = regexp.MustCompile(`(?i)CVE-\d{4}-\d{4,7}`)

type nucleiInfoYAML struct {
	ID   string `yaml:"id"`
	Info struct {
		Name           string `yaml:"name"`
		Severity       string `yaml:"severity"`
		Tags           string `yaml:"tags"`
		Classification struct {
			CVEID []string `yaml:"cve-id"`
		} `yaml:"classification"`
		Reference []string `yaml:"reference"`
	} `yaml:"info"`
}

// nucleiTagsToCategory 按 nuclei tags 映射到 14 归类，命中不到再走关键词推测。
func nucleiTagsToCategory(tags, name string) string {
	t := strings.ToLower(tags + " " + name)
	has := func(words ...string) bool {
		for _, w := range words {
			if strings.Contains(t, w) {
				return true
			}
		}
		return false
	}
	switch {
	case has("deserialization"):
		return "deserialization"
	case has("sqli", "sql-injection"):
		return "sqli"
	case has("ssrf"):
		return "ssrf"
	case has("xxe"):
		return "xxe"
	case has("lfi", "rfi", "traversal", "path-traversal", "file-read", "file-download"):
		return "path-traversal"
	case has("file-upload", "upload"):
		return "file-upload"
	case has("auth-bypass", "auth-bypass", "authentication-bypass", "jwt"):
		return "auth-bypass"
	case has("unauth", "unauthenticated"):
		return "unauthorized"
	case has("default-login", "default-credential", "weak-password"):
		return "weak-password"
	case has("disclosure", "exposure", "info-leak", "information-disclosure"):
		return "info-leak"
	case has("privesc", "privilege-escalation"):
		return "privesc"
	case has("rce"):
		return "rce"
	}
	return GuessPocCategory(t)
}

// extractCVEs 从模板 id / tags / classification 里提取 CVE 编号。
func extractCVEs(id, tags string, cveIDs []string) string {
	found := []string{}
	seen := map[string]bool{}
	push := func(cve string) {
		cve = strings.ToUpper(cve)
		if !seen[cve] {
			seen[cve] = true
			found = append(found, cve)
		}
	}
	for _, c := range cveIDs {
		if cvePattern.MatchString(c) {
			push(cvePattern.FindString(c))
		}
	}
	for _, m := range cvePattern.FindAllString(id+" "+tags, -1) {
		push(m)
	}
	return strings.Join(found, ",")
}

// ImportNucleiTemplates 扫描本机 nuclei 模板目录，把模板元数据索引进
// poc_knowledge（source='nuclei-template', kind='template',
// language='nuclei', code='nuclei-<模板id>'）。已存在的按 code 合并刷新，
// 可重复执行。返回（新增+更新总数，跳过数）。
func (d *DB) ImportNucleiTemplates(ctx context.Context, dir string) (imported, skipped int, err error) {
	dir = os.ExpandEnv(dir)
	entries := []string{}
	walkErr := filepath.WalkDir(dir, func(path string, e os.DirEntry, err error) error {
		if err != nil {
			return nil // 单个坏目录不中断整批
		}
		if e.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") {
			entries = append(entries, path)
		}
		return nil
	})
	if walkErr != nil {
		return 0, 0, walkErr
	}
	for _, path := range entries {
		if err := ctx.Err(); err != nil {
			return imported, skipped, err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			skipped++
			continue
		}
		var tpl nucleiInfoYAML
		if err := yaml.Unmarshal(raw, &tpl); err != nil || strings.TrimSpace(tpl.ID) == "" {
			skipped++
			continue
		}
		id := strings.TrimSpace(tpl.ID)
		cve := extractCVEs(id, tpl.Info.Tags, tpl.Info.Classification.CVEID)
		title := strings.TrimSpace(tpl.Info.Name)
		if title == "" {
			title = id
		}
		rel, _ := filepath.Rel(dir, path)
		refs := []string{}
		for _, r := range tpl.Info.Reference {
			if r = strings.TrimSpace(r); r != "" {
				refs = append(refs, r)
			}
		}
		p := &PocEntry{
			Code:        "nuclei-" + slugPocCode(id),
			Title:       title,
			Kind:        PocKindTemplate,
			Category:    nucleiTagsToCategory(tpl.Info.Tags, title),
			CVE:         cve,
			Severity:    strings.ToLower(strings.TrimSpace(tpl.Info.Severity)),
			Language:    "nuclei",
			Source:      PocSourceNucleiTemplate,
			SourceURL:   strings.Join(refs, "\n"),
			Description: fmt.Sprintf("nuclei 模板 %s（本地模板库 %s）", id, rel),
			Usage:       fmt.Sprintf("nuclei -t %s -u <目标>", rel),
			Path:        rel,
			Tags:        strings.TrimSpace(tpl.Info.Tags),
			CreatedBy:   "nuclei-import",
		}
		if _, _, err := d.SavePoc(ctx, p); err != nil {
			skipped++
			continue
		}
		imported++
	}
	return imported, skipped, nil
}
