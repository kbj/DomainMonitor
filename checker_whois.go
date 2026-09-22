package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
	"unicode/utf16"
)

// defaultNotFoundMarkers WHOIS "未注册" 判定的默认关键词（对全文小写匹配）。
// 个别注册局响应格式特殊时，可在配置里用 notfound_marker 按后缀覆盖。
var defaultNotFoundMarkers = []string{
	"no match", // Verisign: No match for "XXX"、JPRS: No match!!
	"nomatch",
	"not found",
	"no data found",
	"no entries found",
	"no object found",
	"no matching record", // CNNIC: No matching record.
	"nothing found",
	"status: free", // DENIC / SIDN 等
	"查询不到",
	"没有找到",
}

// whoisErrorMarkers 疑似限流/错误响应的关键词，命中则按"查询失败"处理，
// 避免把限流页误判成"已注册"。
var whoisErrorMarkers = []string{
	"limit exceeded",
	"too many requests",
	"quota exceeded",
	"rate limit",
	"maximum requests",
	"connection limit",
	"try again",
	"access denied",
	"query limit",
	"throttl",
	"temporarily unavailable",
}

// registeredMarkers 表明域名已注册的关键词。
var registeredMarkers = []string{
	"domain name:",
	"registrar:",
	"status:",
	"name server",
	"nameserver",
	"nserver",
	"domain:",
}

// WhoisChecker 通过 WHOIS(TCP 43) 查询域名状态。
type WhoisChecker struct {
	Server   string   // 主机名或 host:port
	NotFound []string // 未注册判定关键词（可按后缀覆盖）
}

// NewWhoisChecker 创建 WHOIS 查询器；markers 为空时使用默认词表。
func NewWhoisChecker(server string, markers []string) *WhoisChecker {
	if len(markers) == 0 {
		markers = defaultNotFoundMarkers
	}
	return &WhoisChecker{Server: server, NotFound: markers}
}

// Check 查询域名状态。判定优先级：错误/限流 > 未注册 > 待删除 > 已注册。
func (w *WhoisChecker) Check(ctx context.Context, domain string) (*CheckResult, error) {
	addr := w.Server
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "43")
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("连接 WHOIS 服务器 %s 失败: %w", addr, err)
	}
	defer conn.Close()
	// 读超时兜底：ctx 无 deadline 时最多等 60s，避免服务器不应答时永久阻塞
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(60 * time.Second)
	}
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write([]byte(domain + "\r\n")); err != nil {
		return nil, fmt.Errorf("发送 WHOIS 查询失败: %w", err)
	}
	raw, err := io.ReadAll(conn)
	if err != nil && len(raw) == 0 {
		return nil, fmt.Errorf("读取 WHOIS 响应失败: %w", err)
	}
	// 部分注册局读完响应会直接断开导致 ReadAll 报错，只要拿到数据就继续解析
	return w.parse(decodeWhoisText(raw))
}

// parse 解析 WHOIS 文本。
func (w *WhoisChecker) parse(text string) (*CheckResult, error) {
	lower := strings.ToLower(text)
	trimmed := strings.TrimSpace(lower)
	if len(trimmed) < 10 {
		return nil, fmt.Errorf("WHOIS 响应过短（%d 字节）: %q", len(trimmed), snippet(text, 80))
	}
	for _, m := range whoisErrorMarkers {
		if strings.Contains(lower, m) {
			return nil, fmt.Errorf("WHOIS 疑似限流/错误响应: %q", snippet(text, 120))
		}
	}
	for _, m := range w.NotFound {
		if strings.Contains(lower, m) {
			return &CheckResult{
				Status: StatusAvailable,
				Detail: fmt.Sprintf("WHOIS 命中未注册标记 %q", m),
			}, nil
		}
	}
	if strings.Contains(lower, "pendingdelete") {
		return &CheckResult{Status: StatusPendingDelete,
			Detail: withStatusLine("WHOIS 含待删除(pendingDelete)状态", text)}, nil
	}
	if strings.Contains(lower, "redemptionperiod") {
		return &CheckResult{Status: StatusRedemptionPeriod,
			Detail: withStatusLine("WHOIS 含赎回期(redemptionPeriod)状态", text)}, nil
	}
	for _, m := range registeredMarkers {
		if strings.Contains(lower, m) {
			return &CheckResult{Status: StatusRegistered, Detail: "WHOIS 返回注册信息"}, nil
		}
	}
	// 内容较多但没有任何已知标记：保守按已注册处理（避免误报"可注册"）
	if len(trimmed) > 120 {
		return &CheckResult{Status: StatusRegistered, Detail: "WHOIS 响应未含已知标记，按已注册处理"}, nil
	}
	return nil, fmt.Errorf("无法解析 WHOIS 响应: %q", snippet(text, 120))
}

// withStatusLine 拼接判定前缀与匹配到的原始状态行。
func withStatusLine(prefix, text string) string {
	if line := findStatusLine(text); line != "" {
		return prefix + ": " + strings.TrimSpace(line)
	}
	return prefix
}

// findStatusLine 找出包含待删除/赎回期状态的原始行。
func findStatusLine(text string) string {
	for _, line := range strings.Split(text, "\n") {
		l := strings.ToLower(line)
		if strings.Contains(l, "pendingdelete") || strings.Contains(l, "redemptionperiod") {
			return line
		}
	}
	return ""
}

// decodeWhoisText 解码响应文本。
// 部分注册局（如 CNNIC）以 UTF-16 返回 WHOIS 数据，带 BOM 时先解码再匹配。
func decodeWhoisText(raw []byte) string {
	if len(raw) >= 2 && raw[0] == 0xFF && raw[1] == 0xFE { // UTF-16 LE
		return string(utf16.Decode(leU16(raw[2:])))
	}
	if len(raw) >= 2 && raw[0] == 0xFE && raw[1] == 0xFF { // UTF-16 BE
		return string(utf16.Decode(beU16(raw[2:])))
	}
	return string(raw)
}

func leU16(b []byte) []uint16 {
	out := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		out = append(out, uint16(b[i])|uint16(b[i+1])<<8)
	}
	return out
}

func beU16(b []byte) []uint16 {
	out := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		out = append(out, uint16(b[i])<<8|uint16(b[i+1]))
	}
	return out
}
