package server

import (
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/Autumn-27/norma/skill"
)

// 技能自检：通用检查（SKILL.md 可解析 / 声明的 MCP 已配置启用 / 至少一个
// agent 可见）+ 按技能的依赖映射（环境变量、命令、文件路径）。批量接口
// GET /api/skills/checks 一次返回全部技能状态——列表徽章给一眼结论，详情
// 面板展开缺什么。检查全是本地 stat / LookPath / 读 settings，毫秒级。
//
// 依赖缺失级别：error = 缺了技能无法加载（SKILL.md 坏/声明的 MCP 未配置）；
// warn = 降级可用（缺 env 有手工替代方案、工具二进制未装可后补）——与技能
// 文档的降级口径一致（如 fofa-recon 缺 FOFA_KEY 走 crt.sh 降级路径）。

type skillIssue struct {
	Level  string `json:"level"`  // error | warn
	Label  string `json:"label"`  // 短标签，如「缺 FOFA_KEY」
	Detail string `json:"detail"` // 说明 + 补齐指引
}

type skillCheckResult struct {
	Name   string       `json:"name"`
	OK     bool         `json:"ok"` // 无 error 级问题即为可用（warn 不挡）
	Issues []skillIssue `json:"issues"`
}

// skillDep 是一条依赖声明。kind：env（环境变量，redteam_env 设置页 + 进程
// env 二选一）｜cmd（PATH 命令）｜file（路径，支持 ~ 与 $DSH_HOME 展开）。
// Names 任一命中即通过（any-of，如 chromium 的多平台命令名）。
type skillDep struct {
	Kind   string
	Names  []string
	Label  string
	Level  string // 缺失时级别；空 = warn
	Detail string // 补齐指引（缺失时展示）
}

func depEnv(name, label, detail string) skillDep {
	return skillDep{Kind: "env", Names: []string{name}, Label: label, Detail: detail}
}
func depCmd(label, detail string, cmds ...string) skillDep {
	return skillDep{Kind: "cmd", Names: cmds, Label: label, Detail: detail}
}
func depFile(label, detail string, paths ...string) skillDep {
	return skillDep{Kind: "file", Names: paths, Label: label, Detail: detail}
}

// skillDepRules 按技能性质声明硬依赖。只写「SKILL.md 正文明确依赖、缺了会
// 实际受阻」的项；纯命令拼接类技能（passive-recon/web-fingerprint 等）不加。
// $DSH_HOME 在 file 检查时用 redteam_env 的 DSH_HOME（默认 ~/.dsh）展开。
var skillDepRules = map[string][]skillDep{
	// 侦察测绘
	"fofa-recon": {
		depEnv("FOFA_KEY", "缺 FOFA_KEY", "系统配置→红队环境变量里配置（fofa.info 个人中心→API Key）"),
	},
	"recon-pipeline": {
		depCmd("缺 subfinder", "ProjectDiscovery 子域枚举", "subfinder"),
		depCmd("缺 httpx", "ProjectDiscovery HTTP 探测", "httpx"),
		depCmd("缺 dnsx", "ProjectDiscovery DNS 解析", "dnsx"),
		depCmd("缺 naabu", "ProjectDiscovery 端口扫描", "naabu"),
		depCmd("缺 katana", "ProjectDiscovery 爬虫", "katana"),
	},
	"cn-proxy-pool": {
		depCmd("缺 python3", "代理池抓取脚本需要 python3", "python3"),
	},
	"api-recon": {
		depCmd("缺 python3", "scripts/ 抓取脚本需要 python3", "python3"),
		depCmd("缺 node", "scripts/preload.js 需要 node", "node"),
	},
	// 浏览器
	"browser-automation": {
		depCmd("缺 Chrome/Chromium", "chromium 命令行驱动", "chromium", "chromium-browser", "google-chrome", "google-chrome-stable"),
	},
	"playwright-cli": {
		depCmd("缺 playwright-cli", "浏览器自动化命令行", "playwright-cli"),
	},
	// 扫描检测
	"active-scan": {
		depCmd("缺 nmap", "端口与服务扫描", "nmap"),
	},
	"nuclei-scan": {
		depCmd("缺 nuclei", "模板化漏洞扫描", "nuclei"),
		depFile("缺 nuclei 模板库", "nuclei -update-templates 或指定模板目录",
			"~/.local/nuclei-templates", "~/nuclei-templates", "/usr/share/nuclei-templates"),
	},
	"dir-bruteforce": {
		depCmd("缺 ffuf", "目录/文件爆破", "ffuf"),
	},
	// 漏洞利用与凭据
	"credential-attack": {
		depCmd("缺 hydra", "在线弱口令爆破", "hydra"),
		depCmd("缺 hashcat", "离线哈希破解（缺了 john 可替代）", "hashcat"),
	},
	"lateral-movement": {
		depCmd("缺 Impacket", "PtH/PsExec/WMI 等横向工具（pip install impacket）", "impacket-psexec", "psexec.py"),
	},
	// 隧道（工具二进制由 redteam-setup 安装到 $DSH_HOME/redteam/toolkit）
	"chisel-tunnel": {
		depFile("缺 chisel 二进制", "跑 redteam-setup 技能的 scripts/setup.sh 安装", "$DSH_HOME/redteam/toolkit/chisel/chisel"),
		depEnv("REDTEAM_VPS_HOST", "缺 REDTEAM_VPS_HOST", "隧道落点（user@ip），系统配置→红队环境变量"),
	},
	"frp-tunnel": {
		depFile("缺 frps/frpc 二进制", "跑 redteam-setup 技能的 scripts/setup.sh 安装",
			"$DSH_HOME/redteam/toolkit/frp/frps", "$DSH_HOME/redteam/toolkit/frp/frpc"),
		depEnv("REDTEAM_VPS_HOST", "缺 REDTEAM_VPS_HOST", "VPS 落点（user@ip），系统配置→红队环境变量"),
	},
	"suo5-tunnel": {
		depFile("缺 suo5 二进制", "跑 redteam-setup 技能的 scripts/setup.sh 安装", "$DSH_HOME/redteam/toolkit/suo5/suo5-linux-amd64"),
	},
	// 内网与落地
	"fscan-intranet": {
		depFile("缺 fscan 二进制", "跑 redteam-setup 技能的 scripts/setup.sh 安装", "$DSH_HOME/redteam/toolkit/fscan/fscan"),
	},
	"gogo-intranet": {
		depFile("缺 gogo 二进制", "跑 redteam-setup 技能的 scripts/setup.sh 安装", "$DSH_HOME/redteam/toolkit/gogo/gogo"),
	},
	"shell-handler": {
		depEnv("REDTEAM_VPS_HOST", "缺 REDTEAM_VPS_HOST", "反弹 Shell 落地 VPS（user@ip），系统配置→红队环境变量"),
	},
	"vps-reverse-shell": {
		depEnv("REDTEAM_VPS_HOST", "缺 REDTEAM_VPS_HOST", "落地 VPS（user@ip），系统配置→红队环境变量"),
		depFile("缺 VPS SSH 私钥", "放置到 $DSH_HOME/redteam/toolkit/vps/id_rsa（chmod 600）", "$DSH_HOME/redteam/toolkit/vps/id_rsa"),
	},
	// 引导
	"redteam-setup": {
		depFile("缺 scripts/setup.sh", "环境一键铺装脚本（随技能分发，应始终存在）", "skills/redteam-setup/scripts/setup.sh", "$SELF/scripts/setup.sh"),
	},
}

// skillChecks 对 skillsDir 下每个技能跑完整自检。
func (s *Server) skillChecks(skillsDir string) ([]skillCheckResult, error) {
	entries, err := os.ReadDir(skillsDir)
	if err != nil {
		return nil, err
	}
	reg, _ := skill.LoadDir(skillsDir) // 解析失败的技能靠 name/description 检查兜出

	// 依赖检查要用的上下文：MCP 启用表、可见性、红队环境。
	mcpEnabled := map[string]bool{}
	if mcps, err := s.m.pg.ListMCP(); err == nil {
		for _, m := range mcps {
			mcpEnabled[m.Name] = m.Enabled
		}
	}
	rtEnv := s.m.RedteamEnv() // 已含 DSH_HOME 兜底
	if home, err := os.UserHomeDir(); err == nil {
		if _, ok := rtEnv["DSH_HOME"]; !ok {
			rtEnv["DSH_HOME"] = filepath.Join(home, ".dsh")
		}
	}

	out := []skillCheckResult{}
	for _, e := range entries {
		if !e.IsDir() || !validSkillName(e.Name()) {
			continue
		}
		name := e.Name()
		res := skillCheckResult{Name: name, Issues: []skillIssue{}}

		// ① SKILL.md 可解析且 name/description 非空（norma 规范的硬要求）。
		if reg != nil {
			if sk, ok := reg.Get(name); ok {
				if strings.TrimSpace(sk.Name) == "" || strings.TrimSpace(sk.Description) == "" {
					res.Issues = append(res.Issues, skillIssue{
						Level: "error", Label: "SKILL.md 缺 name/description",
						Detail: "frontmatter 必须声明 name 与 description，否则技能无法被加载",
					})
				}
				// ② 声明的 mcps 必须存在且启用（否则加载时解锁不了工具）。
				for _, m := range sk.MCPs {
					if !mcpEnabled[m] {
						res.Issues = append(res.Issues, skillIssue{
							Level: "error", Label: "MCP「" + m + "」未配置/未启用",
							Detail: "技能 frontmatter 声明了该 MCP；到「MCP」页添加并启用它",
						})
					}
				}
			} else {
				res.Issues = append(res.Issues, skillIssue{
					Level: "error", Label: "SKILL.md 解析失败",
					Detail: "frontmatter 格式错误（须以 --- 开闭），技能不会被加载",
				})
			}
		}

		// ③ 至少一个 agent 可见（否则没人能调用它）。
		if agents, err := s.m.pg.SkillAgents(name); err == nil && len(agents) == 0 {
			res.Issues = append(res.Issues, skillIssue{
				Level: "warn", Label: "无可见 Agent",
				Detail: "没有任何 agent 被授权加载该技能，到技能页「可见性」勾选",
			})
		}

		// ④ 技能特定依赖。
		for _, d := range skillDepRules[name] {
			if hit, why := checkDep(d, rtEnv, skillsDir, name); !hit {
				level := d.Level
				if level == "" {
					level = "warn"
				}
				detail := d.Detail
				if detail == "" {
					detail = why
				}
				res.Issues = append(res.Issues, skillIssue{Level: level, Label: d.Label, Detail: detail})
			}
		}

		// OK = 无 error 级问题（warn 是降级不挡可用性）。
		res.OK = true
		for _, is := range res.Issues {
			if is.Level == "error" {
				res.OK = false
				break
			}
		}
		out = append(out, res)
	}
	return out, nil
}

// checkDep 判断一条依赖是否满足。hit=false 时 why 说明实际缺的是哪个名字。
func checkDep(d skillDep, rtEnv map[string]string, skillsDir, skillName string) (hit bool, why string) {
	for _, n := range d.Names {
		switch d.Kind {
		case "env":
			if v := strings.TrimSpace(rtEnv[n]); v != "" {
				return true, ""
			}
			if v := strings.TrimSpace(os.Getenv(n)); v != "" {
				return true, ""
			}
			why = n + " 未配置"
		case "cmd":
			if _, err := exec.LookPath(n); err == nil {
				return true, ""
			}
			why = "PATH 中找不到 " + n
		case "file":
			p := expandDepPath(n, rtEnv, skillsDir, skillName)
			if st, err := os.Stat(p); err == nil && (st.Mode().IsRegular() || st.IsDir()) {
				return true, ""
			}
			why = "不存在：" + p
		}
	}
	return false, why
}

// expandDepPath 展开依赖路径：$DSH_HOME → redteam_env 的 DSH_HOME（默认
// ~/.dsh）；$SELF → 该技能自身目录（用于"随技能分发"的文件声明）；~ → home。
func expandDepPath(p string, rtEnv map[string]string, skillsDir, skillName string) string {
	if strings.HasPrefix(p, "$SELF") {
		return filepath.Join(skillsDir, skillName, strings.TrimPrefix(p, "$SELF/"))
	}
	if h, ok := rtEnv["DSH_HOME"]; ok && h != "" {
		p = strings.ReplaceAll(p, "$DSH_HOME", h)
	}
	if home, err := os.UserHomeDir(); err == nil {
		p = strings.ReplaceAll(p, "~", home)
	}
	return os.ExpandEnv(p)
}

// pgSkillChecks GET /api/skills/checks — 批量自检（列表徽章 + 详情明细）。
func (s *Server) pgSkillChecks(w http.ResponseWriter, r *http.Request) {
	if s.pg(w) == nil { // 依赖 DB（可见性/MCP）——保持与其他 pg* handler 一致
		return
	}
	checks, err := s.skillChecks(s.skillDir)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"checks": checks})
}
