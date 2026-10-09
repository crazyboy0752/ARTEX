package db

import (
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestPocCategories14(t *testing.T) {
	if len(PocCategories) != 14 {
		t.Fatalf("归类数=%d, want 14", len(PocCategories))
	}
	want := []string{"rce", "deserialization", "file-upload", "sqli", "unauthorized",
		"auth-bypass", "weak-password", "ssrf", "xxe", "path-traversal",
		"info-leak", "privesc", "tunnel", "other"}
	seen := map[string]bool{}
	for i, c := range PocCategories {
		if c.Code != want[i] {
			t.Errorf("归类[%d]=%q, want %q", i, c.Code, want[i])
		}
		if seen[c.Code] {
			t.Errorf("归类重复: %q", c.Code)
		}
		seen[c.Code] = true
		if c.Name == "" || c.Hint == "" {
			t.Errorf("归类 %q 缺中文名或提示", c.Code)
		}
	}
	if normalizePocCategory("rce") != "rce" {
		t.Error("合法归类被改写")
	}
	if normalizePocCategory("RCE ") != "other" {
		t.Error("大小写变体应落 other（入库前由调用方统一小写）")
	}
	if normalizePocCategory("xxx") != "other" || normalizePocCategory("") != "other" {
		t.Error("未知/空归类应落 other")
	}
}

func TestGuessPocCategory(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Struts2 S2-061 命令执行", "rce"},
		// 注意：log4j 按来源仓库的启发式规则落 deserialization（Java 生态桶），
		// 这是迁移兜底逻辑；nuclei 模板走 tags 优先，照样归 rce（见下）。
		{"Apache Log4j2 Remote Code Execution", "deserialization"},
		{"fastjson 反序列化漏洞", "deserialization"},
		{"任意文件上传 getshell", "file-upload"},
		{"SQL注入 union select 拖库", "sqli"},
		{"Redis 未授权访问", "unauthorized"},
		{"JWT 认证绕过", "auth-bypass"},
		{"Tomcat 弱口令爆破", "weak-password"},
		{"SSRF 服务端请求伪造读云元数据", "ssrf"},
		{"XXE 外部实体读取", "xxe"},
		{"目录穿越任意文件读取", "path-traversal"},
		{"配置信息泄露", "info-leak"},
		{"mimikatz 凭据转储横向", "privesc"},
		{"suo5 隧道代理", "tunnel"},
		{"tags: default-login,http", "weak-password"},
		{"完全不相关的描述文字", "other"},
	}
	for _, c := range cases {
		if got := GuessPocCategory(c.in); got != c.want {
			t.Errorf("GuessPocCategory(%q)=%q, want %q", c.in, got, c.want)
		}
	}
	// nuclei tags 优先于关键词推测：log4j 按关键词会落 deserialization，
	// 但模板 tags 明确标了 rce 时以 tags 为准
	if got := nucleiTagsToCategory("cve,cve2021,rce,log4j", "Apache Log4j2 Remote Code Execution"); got != "rce" {
		t.Errorf("nucleiTagsToCategory(rce tags)=%q, want rce", got)
	}
	if got := nucleiTagsToCategory("cve", "Apache Log4j2 Remote Code Execution"); got != "deserialization" {
		t.Errorf("nucleiTagsToCategory 无命中 tags 应回退关键词推测，got %q", got)
	}
}

func TestSlugPocCode(t *testing.T) {
	if got := slugPocCode("../../escaped-poc"); got != "escaped-poc" {
		t.Errorf("路径穿越未净化: %q", got)
	}
	if got := slugPocCode("CVE-2021-44228 log4j rce"); got != "CVE-2021-44228-log4j-rce" {
		t.Errorf("空格应转 -: %q", got)
	}
	if got := slugPocCode("泛微OA_文件上传.py"); got != "泛微OA_文件上传.py" {
		t.Errorf("中文/_/. 应保留: %q", got)
	}
	if _, err := makePocCode("", "", ""); err == nil {
		t.Error("空标题应报错")
	}
	code, err := makePocCode("Shiro 反序列化", "CVE-2016-4437", "")
	if err != nil || !strings.HasPrefix(code, "CVE-2016-4437-") {
		t.Errorf("自动 code 生成异常: %q %v", code, err)
	}
}

func TestBuildPocSearchQuery(t *testing.T) {
	after := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	q, args := buildPocSearchQuery(PocFilter{
		Q: "CVE-2021-44228", Category: "rce,sqli", Layer: PocLayerAll,
		Engagement: "某集团", AssetTarget: "10.0.0.1",
		CreatedAfter: after, VerifiedOnly: true, Limit: 10, Offset: 20,
	})
	for _, want := range []string{
		"poc_search @@ plainto_tsquery('simple'",
		"category IN", "verified = TRUE",
		"engagement_id =", "engagement_name ILIKE",
		"asset_target ILIKE", "created_at >=",
		"ORDER BY verified DESC, hit_count DESC",
	} {
		if !strings.Contains(q, want) {
			t.Errorf("SQL 缺少 %q\n%s", want, q)
		}
	}
	// 参数顺序：q, 6×like, rce, sqli, engagement×2, asset, after, limit, offset
	if len(args) != 15 {
		t.Fatalf("参数个数=%d, want 15: %v", len(args), args)
	}
	if args[0] != "CVE-2021-44228" {
		t.Errorf("args[0]=%v, want 原始 q", args[0])
	}
	if args[7] != "rce" || args[8] != "sqli" {
		t.Errorf("归类参数顺序错: %v", args[7:9])
	}
	if args[13] != 10 || args[14] != 20 {
		t.Errorf("limit/offset 参数错: %v", args[12:])
	}

	// 占位符必须连续且无重复（曾出现 LIMIT $2 OFFSET $2 的 bug）
	nums := regexp.MustCompile(`\$(\d+)`).FindAllStringSubmatch(q, -1)
	seenPH := map[string]bool{}
	for _, m := range nums {
		if seenPH[m[1]] {
			t.Fatalf("占位符 $%s 重复:\n%s", m[1], q)
		}
		seenPH[m[1]] = true
	}
	if len(seenPH) != len(args) {
		t.Fatalf("占位符数=%d, 参数数=%d:\n%s", len(seenPH), len(args), q)
	}

	// 分层
	qNuc, argsNuc := buildPocSearchQuery(PocFilter{Layer: PocLayerNuclei})
	if !strings.Contains(qNuc, "source = $1") {
		t.Errorf("nuclei 层过滤缺失:\n%s", qNuc)
	}
	if len(argsNuc) < 3 || argsNuc[0] != "nuclei-template" {
		t.Errorf("nuclei 层参数错: %v", argsNuc)
	}
	qPoc, _ := buildPocSearchQuery(PocFilter{Layer: PocLayerPOC})
	if !strings.Contains(qPoc, "source <> $1") {
		t.Errorf("poc 层过滤缺失:\n%s", qPoc)
	}
	// 默认 limit
	qDef, argsDef := buildPocSearchQuery(PocFilter{})
	if argsDef[len(argsDef)-2] != 50 {
		t.Errorf("默认 limit 应为 50: %v", argsDef)
	}
	if strings.Contains(qDef, "WHERE") {
		t.Errorf("空过滤器不应有 WHERE:\n%s", qDef)
	}
}

func TestExtractCVEs(t *testing.T) {
	got := extractCVEs("CVE-2021-44228", "cve,cve2021,rce", []string{"CVE-2021-44228"})
	if got != "CVE-2021-44228" {
		t.Errorf("去重失败: %q", got)
	}
	got = extractCVEs("thinkphp-rce", "rce", nil)
	if got != "" {
		t.Errorf("无 CVE 应返回空: %q", got)
	}
}
