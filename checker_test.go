package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ---------- 配置加载 ----------

func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadConfigDefaults(t *testing.T) {
	p := writeTempConfig(t, `
tlds:
  - suffix: com
    whois: whois.verisign-grs.com
domains:
  - Example.COM
`)
	cfg, err := LoadConfig(p, true)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Query.SleepMin.D() != 500*time.Millisecond {
		t.Errorf("sleep_min 默认值错误: %s", cfg.Query.SleepMin)
	}
	if cfg.Query.SleepMax.D() != 5*time.Second {
		t.Errorf("sleep_max 默认值错误: %s", cfg.Query.SleepMax)
	}
	if cfg.Query.Timeout.D() != 10*time.Second {
		t.Errorf("timeout 默认值错误: %s", cfg.Query.Timeout)
	}
	if cfg.Query.Retries != 2 {
		t.Errorf("retries 默认值错误: %d", cfg.Query.Retries)
	}
	if cfg.RemoveWhen != "registered" {
		t.Errorf("remove_when 默认值错误: %s", cfg.RemoveWhen)
	}
	if cfg.Domains[0] != "example.com" {
		t.Errorf("域名未归一化为小写: %s", cfg.Domains[0])
	}
	if tld := cfg.TLDOf("a.example.com"); tld == nil || tld.Suffix != "com" {
		t.Errorf("TLDOf 匹配失败: %v", tld)
	}
}

func TestLoadConfigExplicitValues(t *testing.T) {
	p := writeTempConfig(t, `
query:
  sleep_min: 0.5s
  sleep_max: 5s
  timeout: 10s
  retries: 3
tlds:
  - suffix: co.uk
    whois: whois.nic.uk
  - suffix: uk
    whois: whois.nic.uk
domains:
  - bbc.co.uk
  - top.uk
`)
	cfg, err := LoadConfig(p, true)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Query.Retries != 3 {
		t.Errorf("retries: %d", cfg.Query.Retries)
	}
	// 最长后缀匹配：bbc.co.uk 应匹配 co.uk 而不是 uk
	if tld := cfg.TLDOf("bbc.co.uk"); tld == nil || tld.Suffix != "co.uk" {
		t.Errorf("最长后缀匹配失败: %v", tld)
	}
	if tld := cfg.TLDOf("top.uk"); tld == nil || tld.Suffix != "uk" {
		t.Errorf("后缀匹配失败: %v", tld)
	}
}

func TestLoadConfigRejectUnknownSuffix(t *testing.T) {
	p := writeTempConfig(t, `
tlds:
  - suffix: com
    whois: whois.verisign-grs.com
domains:
  - foo.cn
`)
	if _, err := LoadConfig(p, true); err == nil {
		t.Fatal("未匹配后缀的域名应报错")
	}
}

func TestLoadConfigRejectBadRemoveWhen(t *testing.T) {
	p := writeTempConfig(t, `
remove_when: sometimes
tlds:
  - suffix: com
    whois: whois.verisign-grs.com
domains: [a.com]
`)
	if _, err := LoadConfig(p, true); err == nil {
		t.Fatal("非法 remove_when 应报错")
	}
}

func TestLoadConfigLenientAllowsEmptyDomains(t *testing.T) {
	p := writeTempConfig(t, `
tlds:
  - suffix: com
    whois: whois.verisign-grs.com
`)
	if _, err := LoadConfig(p, false); err != nil {
		t.Fatalf("lenient 模式应允许 domains 为空: %v", err)
	}
	if _, err := LoadConfig(p, true); err == nil {
		t.Fatal("strict 模式下空 domains 应报错")
	}
}

// ---------- 状态归一化 ----------

func TestNormalizeStatus(t *testing.T) {
	cases := []struct {
		in   []string
		want Status
	}{
		{[]string{"pending delete"}, StatusPendingDelete},
		{[]string{"pendingDelete"}, StatusPendingDelete},
		{[]string{"pending-delete"}, StatusPendingDelete},
		{[]string{"redemption period"}, StatusRedemptionPeriod},
		{[]string{"redemptionPeriod"}, StatusRedemptionPeriod},
		{[]string{"client transfer prohibited", "pending delete"}, StatusPendingDelete},
		{[]string{"redemption period", "pending delete"}, StatusPendingDelete}, // pendingDelete 优先
		{[]string{"client delete prohibited"}, StatusRegistered},
		{[]string{"ok", "server transfer prohibited"}, StatusRegistered},
		{nil, StatusRegistered},
	}
	for _, c := range cases {
		if got := NormalizeStatus(c.in); got != c.want {
			t.Errorf("NormalizeStatus(%v) = %s, 期望 %s", c.in, got, c.want)
		}
	}
}

// ---------- RDAP ----------

func TestRDAPBuildURL(t *testing.T) {
	r, err := NewRDAPChecker("https://rdap.example.com/com/v1/domain/{domain}", "")
	if err != nil {
		t.Fatal(err)
	}
	if got := r.buildURL("example.com"); got != "https://rdap.example.com/com/v1/domain/example.com" {
		t.Errorf("模板渲染错误: %s", got)
	}
	r2, _ := NewRDAPChecker("https://rdap.example.com/com/v1/domain/", "")
	if got := r2.buildURL("example.com"); got != "https://rdap.example.com/com/v1/domain/example.com" {
		t.Errorf("拼接错误: %s", got)
	}
}

func TestRDAPCheck(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/domain/pending.com":
			_ = json.NewEncoder(w).Encode(map[string]any{"objectClassName": "domain", "status": []string{"pending delete"}})
		case "/domain/ok.com":
			_ = json.NewEncoder(w).Encode(map[string]any{"objectClassName": "domain", "status": []string{"client delete prohibited"}})
		case "/domain/nostatus.com":
			_ = json.NewEncoder(w).Encode(map[string]any{"objectClassName": "domain"})
		case "/domain/free.com":
			w.WriteHeader(http.StatusNotFound)
		case "/domain/limit.com":
			w.WriteHeader(http.StatusTooManyRequests)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()
	rd, err := NewRDAPChecker(srv.URL+"/domain/{domain}", "")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		domain string
		want   Status
		wantOp bool // 是否期望返回 error（触发降级）
	}{
		{"pending.com", StatusPendingDelete, false},
		{"ok.com", StatusRegistered, false},
		{"nostatus.com", StatusRegistered, false},
		{"free.com", StatusAvailable, false},
		{"limit.com", "", true},
		{"other.com", "", true},
	}
	for _, c := range cases {
		res, err := rd.Check(t.Context(), c.domain)
		if c.wantOp {
			if err == nil {
				t.Errorf("%s: 期望失败但成功了", c.domain)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: 意外失败: %v", c.domain, err)
			continue
		}
		if res.Status != c.want {
			t.Errorf("%s: got %s want %s", c.domain, res.Status, c.want)
		}
	}
}

// ---------- WHOIS ----------

func TestWhoisParse(t *testing.T) {
	w := NewWhoisChecker("whois.example.com", nil)
	cases := []struct {
		name    string
		body    string
		want    Status
		wantErr bool
	}{
		{
			name: "pendingDelete",
			body: "Domain Name: EXAMPLE.COM\r\nRegistry Domain ID: 2336799_DOMAIN_COM-VRSN\r\n" +
				"Domain Status: pendingDelete https://icann.org/epp#pendingDelete\r\n",
			want: StatusPendingDelete,
		},
		{
			name: "redemptionPeriod",
			body: "Domain Status: redemptionPeriod https://icann.org/epp#redemptionPeriod\r\n",
			want: StatusRedemptionPeriod,
		},
		{
			name: "noMatch",
			body: "No match for \"EXAMPLE.COM\".\r\n>>> Last update of whois database: 2025-01-01T00:00:00Z <<<\r\n",
			want: StatusAvailable,
		},
		{
			name: "registered",
			body: "Domain Name: EXAMPLE.COM\r\nRegistrar: EXAMPLE REGISTRAR LLC\r\n" +
				"Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited\r\n",
			want: StatusRegistered,
		},
		{
			name:    "rateLimit",
			body:    "Your connection limit exceeded for WHOIS server. Please try again later.\r\n",
			wantErr: true,
		},
		{
			name:    "tooShort",
			body:    "hello\r\n",
			wantErr: true,
		},
	}
	for _, c := range cases {
		res, err := w.parse(c.body)
		if c.wantErr {
			if err == nil {
				t.Errorf("%s: 期望报错但成功了 (%v)", c.name, res)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: 意外报错: %v", c.name, err)
			continue
		}
		if res.Status != c.want {
			t.Errorf("%s: got %s want %s", c.name, res.Status, c.want)
		}
	}
}

func TestWhoisCheckLive(t *testing.T) {
	// 起一个假 WHOIS 服务器，验证 TCP 流程与判定（支持多次连接）
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 512)
				n, _ := conn.Read(buf)
				domain := string(buf[:n])
				if domain == "free.example\r\n" {
					_, _ = conn.Write([]byte("No match for \"FREE.EXAMPLE\".\r\n"))
				} else {
					_, _ = conn.Write([]byte("Domain Name: SOMETHING.EXAMPLE\r\nDomain Status: ok\r\n"))
				}
			}(conn)
		}
	}()

	w := NewWhoisChecker(ln.Addr().String(), nil) // host:port 形式应保留端口
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	res, err := w.Check(ctx, "free.example")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if res.Status != StatusAvailable {
		t.Errorf("got %s want available", res.Status)
	}
	res2, err := w.Check(ctx, "taken.example")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if res2.Status != StatusRegistered {
		t.Errorf("got %s want registered", res2.Status)
	}
}

// ---------- 降级逻辑 ----------

func TestFallbackRdapToWhois(t *testing.T) {
	// RDAP 返回 500 → 失败 → 应降级到 WHOIS（假服务器返回已注册）
	rdapSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer rdapSrv.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 512)
				_, _ = conn.Read(buf)
				_, _ = conn.Write([]byte("Domain Name: EXAMPLE.COM\r\nRegistrar: X\r\n"))
			}(conn)
		}
	}()

	rd, _ := NewRDAPChecker(rdapSrv.URL+"/domain/{domain}", "")
	w := NewWhoisChecker(ln.Addr().String(), nil)
	c := &DomainChecker{RDAP: rd, Whois: w, Timeout: 3 * time.Second, Retries: 0}

	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	res := c.Check(ctx, "example.com")
	if res.Status != StatusRegistered {
		t.Errorf("got %s want registered", res.Status)
	}
	if res.Channel != "rdap→whois" {
		t.Errorf("channel = %s, 期望 rdap→whois", res.Channel)
	}
}

func TestRetryThenError(t *testing.T) {
	rdapSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer rdapSrv.Close()
	rd, _ := NewRDAPChecker(rdapSrv.URL+"/domain/{domain}", "")
	c := &DomainChecker{RDAP: rd, Timeout: 3 * time.Second, Retries: 1}

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	res := c.Check(ctx, "example.com")
	if res.Status != StatusError {
		t.Errorf("got %s want error", res.Status)
	}
}

// ---------- Server酱³ 推送 ----------

func TestPushResponseHandling(t *testing.T) {
	var mode string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch mode {
		case "ok":
			_, _ = w.Write([]byte(`{"code":0,"message":"success"}`))
		case "badkey":
			_, _ = w.Write([]byte(`{"error":"sendkey not found","code":10003}`)) // HTTP 200 也要报错
		case "http500":
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	n := &Notifier{endpoint: srv.URL, client: &http.Client{}, log: log, enabled: true}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	mode = "ok"
	if err := n.Push(ctx, "t", "d"); err != nil {
		t.Errorf("code=0 应成功, got %v", err)
	}
	mode = "badkey"
	if err := n.Push(ctx, "t", "d"); err == nil {
		t.Error("code=10003 应报错（即使 HTTP 200）")
	}
	mode = "http500"
	if err := n.Push(ctx, "t", "d"); err == nil {
		t.Error("HTTP 500 应报错")
	}
}
