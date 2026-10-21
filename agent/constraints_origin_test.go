package agent

import "testing"

// 约束归属分流，见 constraints.go。
//
// 这组测试守的是整条降级链上最隐蔽的一处：主 agent 的 ToolSet 以 "human" 身份构造，
// 于是模型自己写下的"禁止动真实账户"会以 origin=human 入库，在审计里看起来完全是
// 人的意志，还会被 constraintBlock 渲染成"最高优先级、凌驾一切"。模型的自我审查
// 就这样被洗成了人的授权。

func TestConstraintOrigin(t *testing.T) {
	cases := []struct {
		writer string
		want   string
	}{
		{"human", "agent:mainagent"}, // 主 agent 代写：不是人的直接意志
		{"goals", "goals"},           // 拆解器从人话里抽，保留原样
		{"planner", "planner"},
		{"", "system"},
	}
	for _, c := range cases {
		if got := constraintOrigin(c.writer); got != c.want {
			t.Fatalf("constraintOrigin(%q) = %q, want %q", c.writer, got, c.want)
		}
	}
}

func TestIsHumanConstraint(t *testing.T) {
	// agent:* 一律不算人；human 与 goals 算（goals 是逐字抽取，不是裁量）。
	cases := map[string]bool{
		"human":           true,
		"goals":           true,
		"agent:mainagent": false,
		"planner":         false,
		"":                false,
	}
	for origin, want := range cases {
		if got := isHumanConstraint(origin); got != want {
			t.Fatalf("isHumanConstraint(%q) = %v, want %v", origin, got, want)
		}
	}
}
