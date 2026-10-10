package agent

import (
	"slices"
	"strings"
	"testing"
)

// 红队环境注入：透传基础 env、按 key 追加 K=V、空 map 不动、空 key 跳过。
func TestRedteamEnvEnv(t *testing.T) {
	base := proxyEnv("http://127.0.0.1:8788", "/ca.pem")
	if len(base) == 0 {
		t.Fatal("proxyEnv 应产出代理变量")
	}

	out := redteamEnvEnv(base, map[string]string{"FOFA_KEY": "abc", "DSH_HOME": "/home/u/.dsh"})
	if !slices.Contains(out, "FOFA_KEY=abc") || !slices.Contains(out, "DSH_HOME=/home/u/.dsh") {
		t.Fatalf("红队变量未注入: %v", out)
	}
	if !slices.Contains(out, "HTTP_PROXY=http://127.0.0.1:8788") {
		t.Fatalf("基础代理 env 被破坏: %v", out)
	}

	// 空 map：原样返回（含 nil）。
	if got := redteamEnvEnv(base, nil); len(got) != len(base) {
		t.Fatalf("空 map 应原样返回: %v", got)
	}

	// 空 key 行跳过。
	out2 := redteamEnvEnv(nil, map[string]string{"": "x", "A": "1"})
	if len(out2) != 1 || out2[0] != "A=1" {
		t.Fatalf("空 key 应跳过: %v", out2)
	}

	// 注入的值/键不能带换行（防止一行拆成多条 env = 注入）。
	for _, e := range redteamEnvEnv(nil, map[string]string{"K": "v\nEVIL=1"}) {
		if strings.Contains(e, "\n") {
			t.Fatalf("env 值含换行: %q", e)
		}
		if !strings.Contains(e, "EVIL") { // 换行被清洗为同一条的值内文本
			t.Fatalf("换行值应清洗为单行: %q", e)
		}
	}
	if got := redteamEnvEnv(nil, map[string]string{"BAD\nKEY": "v"}); len(got) != 0 {
		t.Fatalf("含换行的 key 应丢弃: %v", got)
	}
}
