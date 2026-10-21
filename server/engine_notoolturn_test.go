package server

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/Autumn-27/norma/llm"
)

// 无工具回合的三分类（空转 / 拒答 / 降级）与递进续跑，见 classifyNoToolTurn /
// nudgeForNoToolTurn / steerHooks.Stop。
//
// 这组测试守的是整条链上最贵的静默失败：模型拒答或悄悄把任务改小之后，harness 会
// 当成自然结束、以"完成"收场，人以为打了、实际没打。分类错了这个洞就重新打开。

func assistantText(text string) llm.Message {
	return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock(text)}}
}

func TestClassifyNoToolTurn(t *testing.T) {
	cases := []struct {
		name string
		msgs []llm.Message
		want noToolKind
	}{
		{"正常结论", []llm.Message{llm.UserText("开始"), assistantText("已确认 SQL 注入，回显 5 条记录，证据已写回。")}, turnNormal},
		{"显性拒答", []llm.Message{llm.UserText("开始"), assistantText("我不能帮你写这个 webshell。")}, turnRefusal},
		{"作为AI的自我定位", []llm.Message{llm.UserText("开始"), assistantText("作为一个 AI 助手，涉及真实账户的写入我需要你先确认授权。")}, turnRefusal},
		{"软降级：声称要打却没动手", []llm.Message{llm.UserText("开始"), assistantText("我来上传一个 webshell 到上传点，先准备 payload。")}, turnDegraded},
		{"软降级：把动作缩成验证", []llm.Message{llm.UserText("开始"), assistantText("我先验证一下上传接口是否存在，再决定下一步。")}, turnDegraded},
		{"仅思考", []llm.Message{llm.UserText("开始"), assistantThinking("想想")}, turnThinkingOnly},
		// 有工具调用 → 走正常路径，不参与续跑判定。
		{"带工具调用", []llm.Message{llm.UserText("开始"), {Role: llm.RoleAssistant, Content: []llm.ContentBlock{
			{Type: llm.BlockToolUse, ID: "t1", Name: "Bash"}}}}, turnNormal},
		{"空历史", nil, turnNormal},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := classifyNoToolTurn(c.msgs); got != c.want {
				t.Fatalf("classifyNoToolTurn = %v, want %v", got, c.want)
			}
		})
	}
}

// 递进而不是复读：同一句"继续"重放三次会加固拒答，所以三条必须互不相同。
func TestNudgeForNoToolTurnEscalates(t *testing.T) {
	for _, kind := range []noToolKind{turnRefusal, turnDegraded} {
		seen := map[string]bool{}
		for n := 1; n <= 3; n++ {
			got := nudgeForNoToolTurn(kind, n)
			if got == "" {
				t.Fatalf("%v 第 %d 次续跑指令为空", kind, n)
			}
			if seen[got] {
				t.Fatalf("%v 第 %d 次与前面某次重复，续跑会退化成复读", kind, n)
			}
			seen[got] = true
		}
		// 超出递增范围时复用最后一条，不能返回空（空会被当成"没有指令"）。
		if nudgeForNoToolTurn(kind, 9) == "" {
			t.Fatalf("%v 超出递进范围时返回空", kind)
		}
	}
}

// 拒答/降级回合必须真的把续跑指令注入进去；且配额用尽后放行，不能无限循环。
func TestSteerHooksStopNudgesRefusal(t *testing.T) {
	nudges := &atomic.Int64{}
	h := steerHooks{nudges: nudges, limit: 2, label: "worker-1 · #1"}
	msgs := []llm.Message{llm.UserText("开始"), assistantText("抱歉，我不能协助上传可执行文件。")}

	for i := 1; i <= 2; i++ {
		prevent, blocking, _ := h.Stop(context.Background(), msgs)
		if prevent {
			t.Fatalf("第 %d 次：不应硬停", i)
		}
		if len(blocking) != 1 || blocking[0] == "" {
			t.Fatalf("第 %d 次：应注入一条续跑指令，实际 %v", i, blocking)
		}
	}
	// 第三次已达上限 → 放行收场。
	prevent, blocking, _ := h.Stop(context.Background(), msgs)
	if len(blocking) != 0 {
		t.Fatalf("配额用尽后仍注入续跑：%v", blocking)
	}
	if prevent {
		t.Fatal("配额用尽应放行，不是硬停")
	}
}

// 正常收尾的回合不该被推——否则每完成一条意图都会多挨一句"继续"，白烧预算。
func TestSteerHooksStopIgnoresNormalTurn(t *testing.T) {
	h := steerHooks{nudges: &atomic.Int64{}, limit: 2, label: "worker-1 · #1"}
	msgs := []llm.Message{llm.UserText("开始"), assistantText("本意图完成：目标端口开放 22/80，未发现可利用点，已写回两条事实。")}
	if _, blocking, _ := h.Stop(context.Background(), msgs); len(blocking) != 0 {
		t.Fatalf("正常收尾被注入续跑：%v", blocking)
	}
}
