package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newFakeRDAP 返回一个固定返回指定 status 的假 RDAP 服务。
func newFakeRDAP(t *testing.T, statuses ...string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"objectClassName": "domain",
			"status":          statuses,
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// ---------- 阶段变化推送规则 ----------

func TestShouldNotify(t *testing.T) {
	cases := []struct {
		from, to Status
		stage    bool
		want     bool
	}{
		{StatusPendingDelete, StatusAvailable, true, true},
		{StatusPendingDelete, StatusAvailable, false, true},
		{StatusPendingDelete, StatusRegistered, false, true},
		{StatusAvailable, StatusRegistered, false, true},
		{StatusRedemptionPeriod, StatusPendingDelete, true, true},
		{StatusRedemptionPeriod, StatusPendingDelete, false, false}, // 阶段变化但关闭了推送
		{StatusPendingDelete, StatusRedemptionPeriod, false, false},
	}
	for _, c := range cases {
		if got := shouldNotify(c.from, c.to, c.stage); got != c.want {
			t.Errorf("shouldNotify(%s→%s, stage=%v) = %v, 期望 %v", c.from, c.to, c.stage, got, c.want)
		}
	}
}

func TestBuildChangeMessage(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	res := &CheckResult{Status: StatusRedemptionPeriod, Channel: "rdap", Detail: "RDAP status: redemption period"}
	title, desp := buildChangeMessage("a.com", string(StatusPendingDelete), res, "registered", now)
	if !strings.Contains(title, "赎回期") {
		t.Errorf("赎回期标题错误: %s", title)
	}
	if !strings.Contains(desp, "赎回期") || !strings.Contains(desp, "30 天") {
		t.Errorf("赎回期正文错误: %s", desp)
	}

	res2 := &CheckResult{Status: StatusAvailable, Channel: "rdap", Detail: "RDAP 404，域名未注册"}
	title2, desp2 := buildChangeMessage("a.com", string(StatusPendingDelete), res2, "available", now)
	if !strings.Contains(title2, "已可注册") {
		t.Errorf("可注册标题错误: %s", title2)
	}
	if !strings.Contains(desp2, "remove_when=available") {
		t.Errorf("remove_when=available 时正文应说明已移出: %s", desp2)
	}
	_, desp3 := buildChangeMessage("a.com", string(StatusPendingDelete), res2, "registered", now)
	if !strings.Contains(desp3, "监控仍在继续") {
		t.Errorf("默认策略应说明继续监控: %s", desp3)
	}

	res4 := &CheckResult{Status: StatusRegistered, Channel: "whois", Detail: "x"}
	title4, _ := buildChangeMessage("a.com", string(StatusAvailable), res4, "registered", now)
	if !strings.Contains(title4, "已被注册") {
		t.Errorf("已注册标题错误: %s", title4)
	}
}

// ---------- 热更新配置 ----------

func TestReloadConfigDefaults(t *testing.T) {
	p := writeTempConfig(t, `
tlds:
  - suffix: com
    whois: whois.verisign-grs.com
domains: [a.com]
`)
	cfg, err := LoadConfig(p, true)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Reload.IsEnabled() {
		t.Error("热更新默认应启用")
	}
	if cfg.Reload.Interval.D() != time.Second {
		t.Errorf("热更新默认间隔应为 1s, got %s", cfg.Reload.Interval)
	}
	if !cfg.StageChangeNotify() {
		t.Error("阶段变化默认应推送")
	}

	p2 := writeTempConfig(t, `
reload:
  enabled: false
  interval: 5s
notify_stage_change: false
tlds:
  - suffix: com
    whois: whois.verisign-grs.com
domains: [a.com]
`)
	cfg2, err := LoadConfig(p2, true)
	if err != nil {
		t.Fatal(err)
	}
	if cfg2.Reload.IsEnabled() {
		t.Error("reload.enabled: false 应生效")
	}
	if cfg2.Reload.Interval.D() != 5*time.Second {
		t.Errorf("间隔应为 5s, got %s", cfg2.Reload.Interval)
	}
	if cfg2.StageChangeNotify() {
		t.Error("notify_stage_change: false 应生效")
	}
}

func TestReloadConfigRejectTinyInterval(t *testing.T) {
	p := writeTempConfig(t, `
reload:
  interval: 10ms
tlds:
  - suffix: com
    whois: whois.verisign-grs.com
domains: [a.com]
`)
	if _, err := LoadConfig(p, true); err == nil {
		t.Error("过小的 reload.interval 应报错")
	}
}

// ---------- 引擎热更新 ----------

// newTestEngine 组装一个使用假 RDAP 的引擎，并返回写配置的辅助函数。
func newTestEngine(t *testing.T, interval string) (*Engine, *StateStore, func(domains string)) {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	rdap := newFakeRDAP(t, "pending delete")

	writeCfg := func(domains string) {
		t.Helper()
		content := fmt.Sprintf(`query:
  sleep_min: 10ms
  sleep_max: 20ms
  timeout: 3s
reload:
  enabled: true
  interval: %s
tlds:
  - suffix: com
    rdap: %s/domain/{domain}
  - suffix: net
    rdap: %s/domain/{domain}
domains:
%s`, interval, rdap.URL, rdap.URL, domains)
		if err := os.WriteFile(cfgPath, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeCfg("  - a.com\n")

	cfg, err := LoadConfig(cfgPath, true)
	if err != nil {
		t.Fatal(err)
	}
	log := quietLogger()
	state, err := LoadState(filepath.Join(dir, "state.json"), cfg.Domains, log)
	if err != nil {
		t.Fatal(err)
	}
	rt, err := buildRuntime(cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(cfgPath, rt, state, log, new(slog.LevelVar))
	return e, state, writeCfg
}

func TestEngineReloadAppliesNewConfig(t *testing.T) {
	e, state, writeCfg := newTestEngine(t, "100ms")

	// 新增域名（含新后缀 .net）：状态条目与查询器都应就绪
	writeCfg("  - a.com\n  - a2.com\n  - b.net\n")
	if err := e.reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	for _, d := range []string{"a.com", "a2.com", "b.net"} {
		st, ok := state.Get(d)
		if !ok {
			t.Errorf("新增域名 %s 未写入状态", d)
			continue
		}
		if st.Status != string(StatusPendingDelete) {
			t.Errorf("%s 初始状态应为 pending_delete, got %s", d, st.Status)
		}
	}
	if _, ok := e.snap.Load().Checkers["net"]; !ok {
		t.Error("新后缀 net 的查询器未构建")
	}

	// 移除域名：状态应被清理
	writeCfg("  - a2.com\n  - b.net\n")
	if err := e.reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if _, ok := state.Get("a.com"); ok {
		t.Error("移除的域名状态未清理")
	}

	// 非法配置：返回错误且保留当前快照（监控不中断）
	bad := "domains:\n  - x.cn\ntlds:\n  - suffix: com\n    whois: whois.verisign-grs.com\n"
	if err := os.WriteFile(e.path, []byte(bad), 0o644); err != nil {
		t.Fatal(err)
	}
	before := e.snap.Load()
	if err := e.reload(); err == nil {
		t.Error("非法配置应返回错误")
	}
	if e.snap.Load() != before {
		t.Error("非法配置不应替换当前运行时快照")
	}

	// domains 允许临时为空（暂停监控等待下次更新）
	writeCfg("")
	if err := e.reload(); err != nil {
		t.Fatalf("domains 为空应被接受: %v", err)
	}
	if len(e.snap.Load().Cfg.Domains) != 0 {
		t.Error("空 domains 应生效")
	}
}

func TestIntervalDefaultsAndMapping(t *testing.T) {
	p := writeTempConfig(t, `
tlds:
  - suffix: com
    whois: whois.verisign-grs.com
domains: [a.com]
`)
	cfg, err := LoadConfig(p, true)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.IntervalFor(StatusRedemptionPeriod); got != 24*time.Hour {
		t.Errorf("赎回期默认间隔应为 24h, got %s", got)
	}
	if got := cfg.IntervalFor(StatusAvailable); got != 30*time.Minute {
		t.Errorf("可注册默认间隔应为 30m, got %s", got)
	}
	if got := cfg.IntervalFor(StatusPendingDelete); got != 0 {
		t.Errorf("待删除默认间隔应为 0(快节奏), got %s", got)
	}
	if got := cfg.IntervalFor(StatusError); got != 0 {
		t.Errorf("未知状态应走快节奏, got %s", got)
	}

	p2 := writeTempConfig(t, `
query:
  intervals:
    redemption_period: 6h
    pending_delete: 1m
    available: 5m
tlds:
  - suffix: com
    whois: whois.verisign-grs.com
domains: [a.com]
`)
	cfg2, err := LoadConfig(p2, true)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg2.IntervalFor(StatusRedemptionPeriod); got != 6*time.Hour {
		t.Errorf("自定义赎回期间隔未生效: %s", got)
	}
	if got := cfg2.IntervalFor(StatusPendingDelete); got != time.Minute {
		t.Errorf("自定义待删除间隔未生效: %s", got)
	}
	if got := cfg2.IntervalFor(StatusAvailable); got != 5*time.Minute {
		t.Errorf("自定义可注册间隔未生效: %s", got)
	}
}

// newCountingRDAP 返回固定 status 并统计请求次数的假 RDAP 服务。
func newCountingRDAP(t *testing.T, hits *atomic.Int64, statuses ...string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/rdap+json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"objectClassName": "domain",
			"status":          statuses,
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestStatusAwareCheckInterval 验证查询频率确实按状态分级：
// 赎回期只确认一次，待删除期则持续快速轮询。
func TestStatusAwareCheckInterval(t *testing.T) {
	cases := []struct {
		name    string
		status  string
		wantOne bool // true: 期望整段时间内只查询 1 次
	}{
		{"赎回期休眠等待", "redemption period", true},
		{"待删除快速轮询", "pending delete", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			cfgPath := filepath.Join(dir, "config.yaml")
			hits := &atomic.Int64{}
			srv := newCountingRDAP(t, hits, c.status)
			content := fmt.Sprintf(`query:
  sleep_min: 40ms
  sleep_max: 60ms
  timeout: 3s
  intervals:
    redemption_period: 1h
    available: 1h
reload:
  enabled: false
tlds:
  - suffix: com
    rdap: %s/domain/{domain}
domains:
  - a.com
`, srv.URL)
			if err := os.WriteFile(cfgPath, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
			cfg, err := LoadConfig(cfgPath, true)
			if err != nil {
				t.Fatal(err)
			}
			log := quietLogger()
			state, err := LoadState(filepath.Join(dir, "state.json"), cfg.Domains, log)
			if err != nil {
				t.Fatal(err)
			}
			rt, err := buildRuntime(cfg, log)
			if err != nil {
				t.Fatal(err)
			}
			e := NewEngine(cfgPath, rt, state, log, new(slog.LevelVar))

			ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
			defer cancel()
			e.Run(ctx)

			got := hits.Load()
			if c.wantOne {
				if got != 1 {
					t.Errorf("赎回期（1h 间隔）在 1.2s 内应只查询 1 次，实际 %d 次", got)
				}
				if st, _ := state.Get("a.com"); st.Status != string(StatusRedemptionPeriod) {
					t.Errorf("状态应为 redemption_period, got %s", st.Status)
				}
			} else if got < 3 {
				t.Errorf("待删除期应持续快速轮询，1.2s 内只查询了 %d 次", got)
			}
		})
	}
}

func TestEngineHotReloadWhileRunning(t *testing.T) {
	e, state, writeCfg := newTestEngine(t, "100ms")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.watchConfig(ctx, 100*time.Millisecond)
	done := make(chan struct{})
	go func() {
		e.Run(ctx)
		close(done)
	}()

	waitChecked := func(domain string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if st, ok := state.Get(domain); ok && !st.LastChecked.IsZero() {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatalf("域名 %s 在超时前未被查询（热更新未生效）", domain)
	}
	waitChecked("a.com")

	// 运行中改配置文件：watcher 应自动重载，并为新后缀 .net 启动 worker
	writeCfg("  - a.com\n  - b.net\n")
	waitChecked("b.net")

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Error("引擎未在超时内退出")
	}
}

// TestRandomSleepDuration 验证休眠时长的取值区间与随机性（防止被固定成定值）。
func TestRandomSleepDuration(t *testing.T) {
	lo, hi := 500*time.Millisecond, 5*time.Second
	seen := map[time.Duration]bool{}
	for i := 0; i < 500; i++ {
		d := randomSleepDuration(lo, hi)
		if d < lo || d > hi {
			t.Fatalf("随机休眠 %s 越界 [%s, %s]", d, lo, hi)
		}
		seen[d] = true
	}
	if len(seen) < 200 {
		t.Errorf("500 次采样只有 %d 个不同取值，随机性不足（可能被固定了）", len(seen))
	}
	// 等值区间退化为定值
	if got := randomSleepDuration(2*time.Second, 2*time.Second); got != 2*time.Second {
		t.Errorf("等值区间应返回定值, got %s", got)
	}
	// 非法区间（上限小于下限）退化为下限，不 panic
	if got := randomSleepDuration(3*time.Second, time.Second); got != 3*time.Second {
		t.Errorf("非法区间应退化返回下限, got %s", got)
	}
}
