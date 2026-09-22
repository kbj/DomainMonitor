package main

import (
	"context"
	"strings"
	"time"
)

// Status 域名的归一化状态。
type Status string

const (
	StatusRedemptionPeriod Status = "redemption_period" // 赎回期（通常约 30 天后进入待删除期）
	StatusPendingDelete    Status = "pending_delete"    // 待删除（通常约 5 天后释放）
	StatusAvailable        Status = "available"         // 可注册（未注册）
	StatusRegistered       Status = "registered"        // 已注册（正常状态）
	StatusError            Status = "error"             // 查询失败，不代表域名真实状态
)

const userAgent = "DomainMonitor/1.0 (pendingDelete watcher)"

// CheckResult 单次查询的结果。
type CheckResult struct {
	Status  Status `json:"status"`
	Channel string `json:"channel"` // rdap / whois / rdap→whois / -
	Detail  string `json:"detail"`  // 判定依据
}

// normalizeToken 归一化状态字符串：小写并去除空格、连字符、下划线，
// 以兼容 "pending delete" / "pendingDelete" / "pending-delete" 等不同写法。
func normalizeToken(s string) string {
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, "_", "")
	return s
}

// NormalizeStatus 将一组 RDAP/WHOIS 状态串归一化为内部状态。
// pendingDelete 优先于 redemptionPeriod（正常不会共存）；其余（ok/prohibited/hold 等）视为已注册。
func NormalizeStatus(tokens []string) Status {
	redemption := false
	for _, t := range tokens {
		switch normalizeToken(t) {
		case "pendingdelete":
			return StatusPendingDelete
		case "redemptionperiod":
			redemption = true
		}
	}
	if redemption {
		return StatusRedemptionPeriod
	}
	return StatusRegistered
}

// isDeleting 判断是否处于删除流程中（赎回期或待删除期），这两种状态都继续监控。
func isDeleting(s Status) bool {
	return s == StatusRedemptionPeriod || s == StatusPendingDelete
}

// shouldNotify 判断某次状态变化是否需要推送。
// "赎回期 ↔ 待删除"属于删除流程内的阶段变化，可用 notify_stage_change: false 关闭推送。
func shouldNotify(from, to Status, stageNotify bool) bool {
	if !stageNotify && isDeleting(from) && isDeleting(to) {
		return false
	}
	return true
}

// DomainChecker 组合查询器：RDAP 优先，查询失败自动降级 WHOIS；
// 两者都失败时整体按 Retries 重试（退避 2s, 4s, ...）。
type DomainChecker struct {
	RDAP    *RDAPChecker  // 未配置 RDAP 时为 nil
	Whois   *WhoisChecker // 未配置 WHOIS 时为 nil
	Timeout time.Duration // 单次查询超时
	Retries int           // 额外重试次数
}

// Check 查询域名状态，始终返回非 nil 结果（失败时 Status == StatusError）。
func (c *DomainChecker) Check(ctx context.Context, domain string) *CheckResult {
	var lastDetail string
	for attempt := 0; attempt <= c.Retries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return &CheckResult{Status: StatusError, Channel: "-", Detail: "已取消: " + ctx.Err().Error()}
			case <-time.After(time.Duration(attempt) * 2 * time.Second):
			}
		}
		res := c.checkOnce(ctx, domain)
		if res.Status != StatusError {
			return res
		}
		lastDetail = res.Detail
	}
	return &CheckResult{Status: StatusError, Channel: "-", Detail: lastDetail}
}

// checkOnce 执行一轮 RDAP → WHOIS 查询。
func (c *DomainChecker) checkOnce(ctx context.Context, domain string) *CheckResult {
	var errs []string
	if c.RDAP != nil {
		actx, cancel := context.WithTimeout(ctx, c.Timeout)
		res, err := c.RDAP.Check(actx, domain)
		cancel()
		if err == nil {
			res.Channel = "rdap"
			return res
		}
		errs = append(errs, "rdap: "+err.Error())
	}
	if c.Whois != nil {
		actx, cancel := context.WithTimeout(ctx, c.Timeout)
		res, err := c.Whois.Check(actx, domain)
		cancel()
		if err == nil {
			res.Channel = "whois"
			if c.RDAP != nil {
				res.Channel = "rdap→whois" // RDAP 失败后降级成功
			}
			return res
		}
		errs = append(errs, "whois: "+err.Error())
	}
	if len(errs) == 0 {
		errs = append(errs, "该后缀未配置任何查询方式")
	}
	return &CheckResult{Status: StatusError, Channel: "-", Detail: strings.Join(errs, "; ")}
}

// snippet 压缩空白并截断字符串，用于日志与错误信息。
func snippet(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	r := []rune(s)
	if len(r) > n {
		return string(r[:n]) + "..."
	}
	return string(r)
}
