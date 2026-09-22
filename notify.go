package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Server酱³ API: POST https://<uid>.push.ft07.com/send/<sendkey>.send
// 参数: title(必填) / desp(Markdown 正文) / tags / short
// uid 可从 sendkey 提取：sendkey 形如 sctp{uid}t...
var sendkeyUIDRe = regexp.MustCompile(`^sctp(\d+)t`)

// Notifier Server酱³ 推送客户端，并发安全。
type Notifier struct {
	endpoint string // 完整推送 URL
	tags     string
	client   *http.Client
	log      *slog.Logger
	enabled  bool
}

// NewNotifier 创建推送客户端；uid 或 sendkey 缺失时标记为未启用（只记日志不推送）。
func NewNotifier(cfg ServerChanConfig, log *slog.Logger) *Notifier {
	n := &Notifier{
		tags:   cfg.Tags,
		client: &http.Client{},
		log:    log,
	}
	uid := strings.TrimSpace(cfg.UID)
	if uid == "" {
		if m := sendkeyUIDRe.FindStringSubmatch(strings.TrimSpace(cfg.SendKey)); m != nil {
			uid = m[1]
			log.Debug("已从 sendkey 提取 uid", "uid", uid)
		}
	}
	if uid != "" && strings.TrimSpace(cfg.SendKey) != "" {
		n.endpoint = fmt.Sprintf("https://%s.push.ft07.com/send/%s.send", uid, strings.TrimSpace(cfg.SendKey))
		n.enabled = true
	} else {
		log.Warn("Server酱推送未启用（uid/sendkey 缺失），状态变化只记录日志")
	}
	return n
}

// Enabled 报告推送是否可用。
func (n *Notifier) Enabled() string {
	if n.enabled {
		return "已启用"
	}
	return "未启用"
}

// scResponse Server酱³ 响应体。注意：无效 sendkey 也返回 HTTP 200，
// 必须以 body 中的 code 字段为准（0=成功）。
type scResponse struct {
	Code    int    `json:"code"`
	Error   string `json:"error"`
	Message string `json:"message"`
}

// Push 推送一条消息，失败自动重试，最多 3 次。
func (n *Notifier) Push(ctx context.Context, title, desp string) error {
	if !n.enabled {
		return fmt.Errorf("Server酱未配置(uid/sendkey 缺失)，消息未发送: %s", title)
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return fmt.Errorf("推送被取消: %w", lastErr)
			case <-time.After(2 * time.Second):
			}
		}
		form := url.Values{}
		form.Set("title", title)
		form.Set("desp", desp)
		if n.tags != "" {
			form.Set("tags", n.tags)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.endpoint,
			strings.NewReader(form.Encode()))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := n.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("Server酱 HTTP %d: %s", resp.StatusCode, snippet(string(body), 200))
			continue
		}
		var sc scResponse
		if err := json.Unmarshal(body, &sc); err == nil && sc.Code != 0 {
			// 服务端明确拒绝（如 sendkey 无效/配额用尽），重试无意义，直接返回
			msg := sc.Error
			if msg == "" {
				msg = sc.Message
			}
			return fmt.Errorf("Server酱返回错误 code=%d: %s", sc.Code, msg)
		}
		n.log.Debug("Server酱响应", "body", snippet(string(body), 200))
		return nil
	}
	return lastErr
}

// statusCN 内部状态的中文名。
var statusCN = map[Status]string{
	StatusRedemptionPeriod: "赎回期",
	StatusPendingDelete:    "待删除",
	StatusAvailable:        "可注册",
	StatusRegistered:       "已注册",
}

// buildChangeMessage 生成状态变化的推送标题与 Markdown 正文。
func buildChangeMessage(domain, prev string, res *CheckResult, removeWhen string, now time.Time) (string, string) {
	from := prev
	if cn, ok := statusCN[Status(prev)]; ok {
		from = cn
	}
	to := string(res.Status)
	if cn, ok := statusCN[res.Status]; ok {
		to = cn
	}
	head := fmt.Sprintf("**%s**\n\n- 状态变化：%s → **%s**\n- 检测时间：%s\n- 查询通道：%s\n- 判定依据：%s",
		domain, from, to,
		now.Format("2006-01-02 15:04:05"), res.Channel, res.Detail)

	switch res.Status {
	case StatusAvailable:
		tail := "\n\n> 监控仍在继续：若该域名被注册，将再次推送提醒。"
		if removeWhen == "available" {
			tail = "\n\n> 已按 remove_when=available 移出监控列表。"
		}
		return "🎉 " + domain + " 已可注册！", head + tail
	case StatusPendingDelete:
		return "⏳ " + domain + " 已进入待删除期",
			head + "\n\n> 此阶段通常约 5 天后释放，请留意后续“可注册”提醒。"
	case StatusRedemptionPeriod:
		return "🔔 " + domain + " 当前处于赎回期",
			head + "\n\n> 赎回期通常约 30 天，之后才进入待删除期。"
	default: // registered
		return "⚠️ " + domain + " 已被注册", head + "\n\n> 已自动移出监控列表。"
	}
}
