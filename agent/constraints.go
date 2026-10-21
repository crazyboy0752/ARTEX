package agent

import (
	"strings"

	"github.com/Autumn-27/artex/db"
)

// constraintOrigin 把"写作者"翻译成归属标记。
//
// 这里是整条降级链上最隐蔽的一处：主 agent 的 ToolSet 原先以 "human" 身份构造
// (mainagent.go 的 NewToolSet(ts,"human"))，于是模型自己写下的"禁止对真实账户做写
// 操作"会以 origin=human 入库 —— 在审计里看起来完全是人的意志，而 constraintBlock
// 又会把它渲染成"最高优先级、凌驾于一切探索启发式"。模型的自保判断就这样被洗成了
// 人的授权，且此后每一轮都压在人的指令之上，还会自我强化（约束越注入 → 模型越保守
// → 写出越多约束）。
//
// 现在按来源分开：只有 UI/API 里人手工登记（server/constraints_api.go 传 "human"）
// 才算 human；模型代写一律 "agent:<key>"，渲染时降级为注意事项。
func constraintOrigin(writer string) string {
	if writer == "" {
		return "system"
	}
	if writer == "human" {
		return "agent:mainagent" // 主 agent 代写：不是人的直接意志
	}
	return writer
}

// isHumanConstraint 判断一条约束是否真的来自人。goals 也算：拆解器是从人的任务目标/
// 描述里【逐字抽取】约束，属于人说过的话的搬运，不是它自己的裁量。
func isHumanConstraint(origin string) bool {
	return origin == "human" || origin == "goals"
}

// constraintBlock renders this task's operation constraints (task_constraints) as a
// high-priority block appended to the planner/worker system prompt. allow/deny are
// grouped; empty string when there are no constraints (or ts is nil). The framing
// deliberately puts these ABOVE the exploration/expansion heuristics so a declared
// boundary wins the tug-of-war against "chase another entry surface".
//
// 但只有人的约束配得上这个语气。模型自己写的（origin=agent:*）单独成一段弱语气：
// 它仍然可见（可能确实是有用的观察），但不再能冒充"人的红线"去压掉人后来的指令。
func constraintBlock(ts *db.ExplorationStore) string {
	if ts == nil {
		return ""
	}
	rows, err := ts.ListConstraints()
	if err != nil || len(rows) == 0 {
		return ""
	}
	var allow, deny, soft []string
	for _, c := range rows {
		text := strings.TrimSpace(c.Text)
		if text == "" {
			continue
		}
		if !isHumanConstraint(c.Origin) {
			soft = append(soft, "- ["+c.Kind+"] "+text)
			continue
		}
		if c.Kind == "allow" {
			allow = append(allow, "- "+text)
		} else {
			deny = append(deny, "- "+text)
		}
	}
	if len(allow) == 0 && len(deny) == 0 && len(soft) == 0 {
		return ""
	}
	var b strings.Builder
	if len(allow) > 0 || len(deny) > 0 {
		b.WriteString("\n\n【操作约束（人的要求，最高优先级，凌驾于下方一切探索/拓面启发式；每生成一条意图、每执行一个动作前都必须先自检是否违反，违反即不得进行）】：")
		if len(allow) > 0 {
			b.WriteString("\n允许的操作：\n")
			b.WriteString(strings.Join(allow, "\n"))
		}
		if len(deny) > 0 {
			b.WriteString("\n禁止的操作：\n")
			b.WriteString(strings.Join(deny, "\n"))
		}
		b.WriteString("\n（发现约束之外的新目标/新端口/新主机，不等于获得授权：除非它落在上述允许范围内，否则记为 out-of-scope 事实并跳过，不得为其派生意图或执行动作。）")
	}
	if len(soft) > 0 {
		b.WriteString("\n\n【执行过程中的注意事项（非人的指令，优先级低于上面的操作约束与人的明确要求；与之冲突时一律以人为准）】：\n")
		b.WriteString(strings.Join(soft, "\n"))
	}
	return b.String()
}
