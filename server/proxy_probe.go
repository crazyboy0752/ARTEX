package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Autumn-27/artex/traffic"
	"golang.org/x/net/proxy"
)

// proxyProbeResult is the JSON shape returned by POST /api/settings/proxy-egress.
// It reports whether a configured egress proxy actually carries traffic out, and
// — when it does — the observed public egress IP, so the console can show
// "配置已生效 / 不生效" instead of only echoing the saved string.
type proxyProbeResult struct {
	OK        bool   `json:"ok"`        // 拨号并收到 HTTP 响应即 true（与出口 IP 是否可解析无关）
	Reachable bool   `json:"reachable"` // 代理端点是否接受 TCP 连接
	EgressIP  string `json:"egress_ip"` // 经代理观察到的公网出口 IP（解析失败时为空）
	DirectIP  string `json:"direct_ip"` // 本机直连出口 IP（对照组；失败时为空）
	Error     string `json:"error"`     // 失败原因（中文，直接给用户看）
	ElapsedMS int64  `json:"elapsed_ms"`
}

// proxyEgressProbeURL is the third-party endpoint used to read back the public IP.
// It is deliberately an external service: the whole point is to observe the IP the
// target would see, which a loopback probe cannot do.
const proxyEgressProbeURL = "https://api.ipify.org"

// testProxyEgress dials through the given proxy (empty = direct) and reports the
// observed egress IP. It mirrors the real egress path rather than only checking
// that the port accepts a connection: a live listener whose upstream link is dead
// (a half-open ssh -D tunnel) still passes a bare TCP check but fails every
// request, which is exactly the failure the watchdog cannot see.
//
// The proxy is taken from the request body so one endpoint serves every egress
// path the console exposes (全局代理 / 网络搜索代理 / 每条 LLM 配置的代理); the
// caller passes the saved value or a form draft. Empty means the direct route.
func (s *Server) testProxyEgress(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Proxy *string `json:"proxy"`
	}
	// Empty body is fine — an omitted proxy means "test the direct route".
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
		writeErr(w, 400, err.Error())
		return
	}
	raw := ""
	if req.Proxy != nil {
		raw = strings.TrimSpace(*req.Proxy)
	}

	start := time.Now()
	res := probeEgress(r.Context(), raw)
	res.ElapsedMS = time.Since(start).Milliseconds()

	writeJSON(w, 200, res)
}

// probeEgress performs the actual dial+fetch. It never returns an error status:
// failures are reported inside the struct so the UI always has a structured answer.
func probeEgress(ctx context.Context, raw string) proxyProbeResult {
	raw = strings.TrimSpace(raw)
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	res := proxyProbeResult{}
	// Direct-egress baseline, so the caller can tell "proxy works" from "proxy is a
	// no-op that silently forwards through the host's own route".
	res.DirectIP = fetchEgressIP(ctx, nil)

	if raw == "" {
		res.OK = res.DirectIP != ""
		res.Reachable = true
		if !res.OK {
			res.Error = "未配置代理（直连）且直连探测失败，请检查本机网络"
		}
		return res
	}

	u, err := traffic.ValidateProxyURL(raw)
	if err != nil {
		res.Error = err.Error()
		return res
	}

	// For SOCKS5, check the local listener first to distinguish a stopped watchdog
	// from a live endpoint whose upstream request is failing.
	if u.Scheme == "socks5" {
		host := socks5DialAddress(u)
		if c, derr := net.DialTimeout("tcp", host, 5*time.Second); derr != nil {
			res.Error = fmt.Sprintf("代理端口不可达（%s）：%v", host, derr)
			return res
		} else {
			_ = c.Close()
		}
		res.Reachable = true
	}

	client, err := proxyHTTPClient(u)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.EgressIP = fetchEgressIP(ctx, client)
	if res.EgressIP == "" {
		res.Error = "代理端口可达，但经代理出网失败（隧道可能已断或认证失败）"
		return res
	}
	res.OK = true
	return validateProxyEgress(raw, res)
}

func validateProxyEgress(raw string, res proxyProbeResult) proxyProbeResult {
	if strings.TrimSpace(raw) != "" && res.DirectIP != "" && res.EgressIP == res.DirectIP {
		res.OK = false
		res.Error = "代理已连通，但出口 IP 与本机直连相同 —— 流量未真正经代理出网"
	}
	return res
}

func socks5DialAddress(u *url.URL) string {
	port := u.Port()
	if port == "" {
		port = "1080"
	}
	return net.JoinHostPort(u.Hostname(), port)
}

// proxyHTTPClient builds an *http.Client that routes through u. socks5 is dialed
// by x/net/proxy (the same scheme the traffic MITM accepts); http/https use the
// standard transport Proxy field. No env-var fallback: the probe must reflect the
// configured proxy exactly, not an HTTP_PROXY that happens to be in the process env.
func proxyHTTPClient(u *url.URL) (*http.Client, error) {
	tr := &http.Transport{}
	switch u.Scheme {
	case "socks5":
		// x/net/proxy resolves names at the proxy, which is what a jump host wants
		// (target-side DNS).
		dialer, err := proxy.SOCKS5("tcp", u.Host, socksAuth(u), proxy.Direct)
		if err != nil {
			return nil, fmt.Errorf("构建 socks5 拨号器失败：%w", err)
		}
		if cd, ok := dialer.(proxy.ContextDialer); ok {
			tr.DialContext = cd.DialContext
		} else {
			tr.DialContext = func(_ context.Context, network, addr string) (net.Conn, error) {
				return dialer.Dial(network, addr)
			}
		}
	case "http", "https":
		tr.Proxy = http.ProxyURL(u)
	default:
		return nil, fmt.Errorf("不支持的代理协议 %q（支持 http / https / socks5）", u.Scheme)
	}
	return &http.Client{Transport: tr, Timeout: 12 * time.Second}, nil
}

// socksAuth extracts user:pass from a proxy URL, or nil when absent.
func socksAuth(u *url.URL) *proxy.Auth {
	if u.User == nil {
		return nil
	}
	pw, _ := u.User.Password()
	return &proxy.Auth{User: u.User.Username(), Password: pw}
}

// fetchEgressIP GETs the probe URL through client (nil = direct) and returns the
// trimmed IP, or "" on any failure.
func fetchEgressIP(ctx context.Context, client *http.Client) string {
	if client == nil {
		client = &http.Client{Timeout: 12 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, proxyEgressProbeURL, nil)
	if err != nil {
		return ""
	}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
