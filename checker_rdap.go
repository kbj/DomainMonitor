package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// RDAPChecker 通过 RDAP(HTTP) 查询域名状态。
type RDAPChecker struct {
	client *http.Client
	tmpl   string // RDAP 地址模板，支持 {domain} 占位符
}

// NewRDAPChecker 创建 RDAP 查询器；proxy 为空则直连。
func NewRDAPChecker(rdapURL, proxy string) (*RDAPChecker, error) {
	transport := &http.Transport{}
	if proxy != "" {
		pu, err := url.Parse(proxy)
		if err != nil {
			return nil, fmt.Errorf("解析 RDAP 代理地址失败: %w", err)
		}
		transport.Proxy = http.ProxyURL(pu)
	}
	return &RDAPChecker{
		client: &http.Client{Transport: transport},
		tmpl:   rdapURL,
	}, nil
}

type rdapDomainDoc struct {
	ObjectClassName string   `json:"objectClassName"`
	Status          []string `json:"status"`
}

// Check 查询域名。200 → 解析 status 数组；404 → 可注册；
// 其余情况返回 error，由上层降级 WHOIS 或重试。
func (r *RDAPChecker) Check(ctx context.Context, domain string) (*CheckResult, error) {
	u := r.buildURL(domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("构造 RDAP 请求失败: %w", err)
	}
	req.Header.Set("Accept", "application/rdap+json")
	req.Header.Set("User-Agent", userAgent)
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("RDAP 请求失败: %w", err)
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusNotFound:
		// 404 是确定性的"未注册"结论，不需要降级
		return &CheckResult{Status: StatusAvailable, Detail: "RDAP 404，域名未注册"}, nil

	case resp.StatusCode == http.StatusOK:
		body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		if err != nil {
			return nil, fmt.Errorf("读取 RDAP 响应失败: %w", err)
		}
		var doc rdapDomainDoc
		if err := json.Unmarshal(body, &doc); err != nil {
			return nil, fmt.Errorf("解析 RDAP JSON 失败: %w", err)
		}
		if len(doc.Status) == 0 {
			return &CheckResult{Status: StatusRegistered, Detail: "RDAP 200，status 为空"}, nil
		}
		return &CheckResult{
			Status: NormalizeStatus(doc.Status),
			Detail: "RDAP status: " + strings.Join(doc.Status, ", "),
		}, nil

	case resp.StatusCode == http.StatusTooManyRequests:
		return nil, fmt.Errorf("RDAP 限流 (HTTP 429)")

	default:
		return nil, fmt.Errorf("RDAP HTTP %d", resp.StatusCode)
	}
}

// buildURL 渲染 RDAP URL：有 {domain} 占位符则替换，否则拼接在末尾。
func (r *RDAPChecker) buildURL(domain string) string {
	if strings.Contains(r.tmpl, "{domain}") {
		return strings.ReplaceAll(r.tmpl, "{domain}", domain)
	}
	return strings.TrimRight(r.tmpl, "/") + "/" + domain
}
