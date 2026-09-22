package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// errorNotifyThreshold 连续失败达到该次数时（若 notify_on_error 开启）推送一次提醒。
const errorNotifyThreshold = 20

// idleWaitChunk 所有域名都未到期时的单次最长休眠。
// 分片休眠是为了让热更新新增的域名/IP 能及时被开始监控，而不是干等到几小时后。
const idleWaitChunk = 10 * time.Second

// Runtime 一次配置加载构建出的不可变运行时快照。
// 热更新时整体替换；worker 每轮都读取最新快照，因此参数变更立即生效。
type Runtime struct {
	Cfg      *Config
	Checkers map[string]*DomainChecker // suffix → 组合查询器
	Notifier *Notifier
}

// buildRuntime 根据配置构建运行时快照。
func buildRuntime(cfg *Config, log *slog.Logger) (*Runtime, error) {
	checkers := make(map[string]*DomainChecker, len(cfg.TLDs))
	for _, tld := range cfg.TLDs {
		c, err := buildChecker(cfg, tld)
		if err != nil {
			return nil, err
		}
		checkers[tld.Suffix] = c
	}
	return &Runtime{
		Cfg:      cfg,
		Checkers: checkers,
		Notifier: NewNotifier(cfg.ServerChan, log),
	}, nil
}

// buildChecker 按后缀配置构造组合查询器（RDAP 优先，WHOIS 降级）。
func buildChecker(cfg *Config, tld TLDConfig) (*DomainChecker, error) {
	c := &DomainChecker{Timeout: cfg.Query.Timeout.D(), Retries: cfg.Query.Retries}
	if tld.RDAP != "" {
		rc, err := NewRDAPChecker(tld.RDAP, cfg.Query.Proxy)
		if err != nil {
			return nil, fmt.Errorf("后缀 %s: %w", tld.Suffix, err)
		}
		c.RDAP = rc
	}
	if tld.Whois != "" {
		c.Whois = NewWhoisChecker(tld.Whois, tld.NotFoundMarkers)
	}
	return c, nil
}

// Engine 监控引擎：不同后缀并发、同一后缀内严格串行；支持配置文件热更新。
type Engine struct {
	path  string
	state *StateStore
	log   *slog.Logger
	level *slog.LevelVar

	snap     atomic.Pointer[Runtime] // 当前生效的配置快照
	reloadCh chan struct{}           // 热更新信号（唤醒调度器启动新后缀 worker）

	mu      sync.Mutex
	running map[string]bool // suffix → worker 是否存活
	wg      sync.WaitGroup

	errMu  sync.Mutex
	errCnt map[string]int // domain → 连续失败次数
}

// NewEngine 创建监控引擎；rt 为初始运行时快照。
func NewEngine(path string, rt *Runtime, state *StateStore, log *slog.Logger, level *slog.LevelVar) *Engine {
	e := &Engine{
		path:     path,
		state:    state,
		log:      log,
		level:    level,
		reloadCh: make(chan struct{}, 1),
		running:  map[string]bool{},
		errCnt:   map[string]int{},
	}
	e.snap.Store(rt)
	return e
}

// Run 阻塞直到所有后缀都无待监控域名，或 ctx 被取消。
func (e *Engine) Run(ctx context.Context) {
	e.startWorkers(ctx, e.snap.Load())
	for {
		select {
		case <-ctx.Done():
			e.wg.Wait()
			return
		case <-e.reloadCh:
			e.startWorkers(ctx, e.snap.Load())
		}
	}
}

// startWorkers 为"有活跃域名但尚无 worker"的后缀启动 goroutine。
func (e *Engine) startWorkers(ctx context.Context, rt *Runtime) {
	if ctx.Err() != nil {
		return
	}
	for suffix := range e.suffixesWithActiveDomains(rt) {
		e.mu.Lock()
		if e.running[suffix] {
			e.mu.Unlock()
			continue
		}
		e.running[suffix] = true
		e.mu.Unlock()

		e.wg.Add(1)
		go func(suffix string) {
			defer e.wg.Done()
			defer e.markStopped(suffix)
			e.runTLD(ctx, suffix)
		}(suffix)
	}
}

// markStopped 记录 worker 已退出，并触发一次调度器复查。
func (e *Engine) markStopped(suffix string) {
	e.mu.Lock()
	delete(e.running, suffix)
	e.mu.Unlock()
	select {
	case e.reloadCh <- struct{}{}:
	default:
	}
}

// runTLD 单个后缀的监控主循环：轮询本后缀域名，组内串行。
func (e *Engine) runTLD(ctx context.Context, suffix string) {
	log := e.log.With("suffix", suffix)
	rt := e.snap.Load()
	log.Info("后缀监控启动", "domains", strings.Join(e.activeSuffixDomains(rt, suffix), ", "))

	for {
		if ctx.Err() != nil {
			return
		}
		rt = e.snap.Load() // 每轮取最新快照（热更新立即生效）
		checker := rt.Checkers[suffix]
		if checker == nil {
			log.Error("缺少该后缀的查询器，停止")
			return
		}
		list := e.activeSuffixDomains(rt, suffix) // 每轮重算，剔除已移除域名
		if len(list) == 0 {
			log.Info("该后缀已无待监控域名，停止")
			return
		}
		processed, skipped := e.processRound(ctx, rt, checker, list)
		if ctx.Err() != nil {
			return
		}
		if processed == 0 && skipped > 0 {
			// 本轮没有任何域名到期：睡到最早的到期时间（分片），避免空转
			e.waitIdle(ctx, rt, list)
		}
	}
}

// processRound 顺序检查一轮列表。是否查询由域名当前状态对应的检查间隔决定，
// 返回 (本轮已查询数, 因未到检查时间而跳过数)。
func (e *Engine) processRound(ctx context.Context, rt *Runtime, checker *DomainChecker, list []string) (int, int) {
	processed, skipped := 0, 0
	for _, d := range list {
		if ctx.Err() != nil {
			return processed, skipped
		}
		st, ok := e.state.Get(d)
		if ok && st.Removed {
			continue // 已移出监控列表
		}
		if e.dueWait(rt, st) > 0 {
			skipped++ // 未到该状态对应的检查间隔
			continue
		}
		e.processDomain(ctx, rt, checker, d)
		processed++
		if ctx.Err() != nil {
			return processed, skipped
		}
		e.sleepRandom(ctx, rt) // 每次查询完成后随机休眠，再启动下一次
	}
	return processed, skipped
}

// dueWait 返回域名距离下次可查询还需等待的时间；已到期返回 0。
// 间隔按域名当前状态取：赎回期 24h、可注册 30m、待删除期用快速随机节奏。
func (e *Engine) dueWait(rt *Runtime, st DomainState) time.Duration {
	interval := rt.Cfg.IntervalFor(Status(st.Status))
	if interval <= 0 {
		return 0
	}
	if wait := time.Until(st.LastChecked.Add(interval)); wait > 0 {
		return wait
	}
	return 0
}

// processDomain 查询单个域名并处理结果（状态比对、推送、移除）。
func (e *Engine) processDomain(ctx context.Context, rt *Runtime, checker *DomainChecker, domain string) {
	res := checker.Check(ctx, domain)
	now := time.Now()

	if res.Status == StatusError {
		cnt := e.bumpErr(domain)
		e.log.Warn("查询失败", "domain", domain, "连续失败次数", cnt, "detail", res.Detail)
		e.state.Touch(domain, now) // 失败也计入最小检查间隔
		if rt.Cfg.NotifyOnError && cnt == errorNotifyThreshold {
			pushCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
			err := rt.Notifier.Push(pushCtx, "⚠️ 查询持续失败: "+domain,
				fmt.Sprintf("域名 **%s** 已连续 %d 次查询失败，请检查网络或注册局服务状态。\n\n最近错误：%s",
					domain, cnt, res.Detail))
			cancel()
			if err != nil {
				e.log.Error("推送失败", "domain", domain, "err", err)
			}
			e.resetErr(domain) // 重置计数，避免连续刷屏
		}
		return
	}
	e.resetErr(domain)

	changed, prev := e.state.Record(domain, res.Status, res.Channel, res.Detail, now)
	if !changed {
		e.log.Debug("状态未变化", "domain", domain, "status", string(res.Status),
			"channel", res.Channel, "detail", res.Detail)
		return
	}
	e.log.Info("状态变化", "domain", domain, "from", prev, "to", string(res.Status),
		"channel", res.Channel, "detail", res.Detail)
	e.onStateChange(ctx, rt, domain, prev, res)
}

// onStateChange 按配置推送状态变化通知，并在终态时移出监控列表。
func (e *Engine) onStateChange(ctx context.Context, rt *Runtime, domain, prev string, res *CheckResult) {
	if shouldNotify(Status(prev), res.Status, rt.Cfg.StageChangeNotify()) {
		title, desp := buildChangeMessage(domain, prev, res, rt.Cfg.RemoveWhen, time.Now())
		pushCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		err := rt.Notifier.Push(pushCtx, title, desp)
		cancel()
		if err != nil {
			e.log.Error("推送失败", "domain", domain, "err", err)
		} else {
			e.log.Info("推送成功", "domain", domain, "title", title)
		}
	} else {
		e.log.Info("阶段变化（notify_stage_change=false，不推送）", "domain", domain, "from", prev, "to", string(res.Status))
	}

	remove := res.Status == StatusRegistered ||
		(res.Status == StatusAvailable && rt.Cfg.RemoveWhen == "available")
	if remove {
		if err := e.state.MarkRemoved(domain); err != nil {
			e.log.Error("写入状态文件失败", "domain", domain, "err", err)
		}
		e.log.Info("已移出监控列表", "domain", domain)
	}
}

// suffixesWithActiveDomains 返回当前仍有活跃域名的后缀集合。
func (e *Engine) suffixesWithActiveDomains(rt *Runtime) map[string]bool {
	out := map[string]bool{}
	for _, d := range rt.Cfg.Domains {
		tld := rt.Cfg.TLDOf(d)
		if tld == nil {
			continue
		}
		if st, ok := e.state.Get(d); ok && st.Removed {
			continue
		}
		out[tld.Suffix] = true
	}
	return out
}

// activeSuffixDomains 返回指定后缀下未移除的域名（保持配置顺序）。
func (e *Engine) activeSuffixDomains(rt *Runtime, suffix string) []string {
	var out []string
	for _, d := range rt.Cfg.Domains {
		tld := rt.Cfg.TLDOf(d)
		if tld == nil || tld.Suffix != suffix {
			continue
		}
		if st, ok := e.state.Get(d); ok && !st.Removed {
			out = append(out, d)
		}
	}
	return out
}

// randomSleepDuration 在 [lo, hi] 内随机取值；区间非法时退化为 lo。
// 使用 math/rand/v2 的全局源：它由运行时熵自动播种（无需也无法手动 Seed），
// 因此每次进程启动的序列不同，且全局源内部加锁、多后缀 worker 并发调用是安全的。
func randomSleepDuration(lo, hi time.Duration) time.Duration {
	if hi <= lo {
		return lo
	}
	return lo + time.Duration(rand.Float64()*float64(hi-lo))
}

// sleepRandom 在 [sleep_min, sleep_max] 内随机休眠，可被 ctx 打断。
// 每次查询完成后都重新抽一次，同一个进程内不会重复固定值。
func (e *Engine) sleepRandom(ctx context.Context, rt *Runtime) {
	d := randomSleepDuration(rt.Cfg.Query.SleepMin.D(), rt.Cfg.Query.SleepMax.D())
	e.log.Debug("查询完成，随机休眠", "duration", d.Round(time.Millisecond))
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

// waitIdle 在"本轮所有域名都未到期"时休眠：等到最早到期，或最多 idleWaitChunk。
func (e *Engine) waitIdle(ctx context.Context, rt *Runtime, list []string) {
	wait := idleWaitChunk
	for _, d := range list {
		st, ok := e.state.Get(d)
		if !ok || st.Removed {
			continue
		}
		if w := e.dueWait(rt, st); w > 0 && w < wait {
			wait = w
		}
	}
	if wait < time.Second {
		wait = time.Second // 保护，避免意外空转
	}
	e.log.Debug("等待下次检查", "wait", wait.Round(time.Second))
	select {
	case <-ctx.Done():
	case <-time.After(wait):
	}
}

func (e *Engine) bumpErr(domain string) int {
	e.errMu.Lock()
	defer e.errMu.Unlock()
	e.errCnt[domain]++
	return e.errCnt[domain]
}

func (e *Engine) resetErr(domain string) {
	e.errMu.Lock()
	defer e.errMu.Unlock()
	delete(e.errCnt, domain)
}

// ---------- 配置热更新 ----------

// watchConfig 轮询配置文件，内容变化时热更新。
// 用"内容哈希"而不是 fsnotify：对编辑器改名保存、挂载卷替换等场景同样有效，且零依赖。
func (e *Engine) watchConfig(ctx context.Context, interval time.Duration) {
	if interval < 100*time.Millisecond {
		interval = time.Second
	}
	e.log.Info("配置热更新已启用", "文件", e.path, "轮询间隔", interval)
	last, _ := e.fileDigest()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			digest, err := e.fileDigest()
			if err != nil {
				e.log.Debug("读取配置文件失败（下次重试）", "err", err)
				continue
			}
			if digest == last {
				continue
			}
			last = digest // 无论成败都记录，避免同一个坏文件反复刷日志
			if err := e.reload(); err != nil {
				e.log.Error("配置热更新失败，继续使用旧配置", "err", err)
			}
		}
	}
}

// reload 重新加载配置并原子应用。先校验再整体替换：新配置非法时旧配置继续生效，
// 监控不中断。
func (e *Engine) reload() error {
	cfg, err := LoadConfig(e.path, false) // 允许 domains 临时为空（暂停监控）
	if err != nil {
		return err
	}
	rt, err := buildRuntime(cfg, e.log)
	if err != nil {
		return err
	}
	added, dropped := e.state.Sync(cfg.Domains, time.Now())

	old := e.snap.Load()
	e.snap.Store(rt)
	if e.level != nil {
		e.level.Set(parseLevel(cfg.LogLevel))
	}
	e.logDiff(old, rt, added, dropped)

	select {
	case e.reloadCh <- struct{}{}: // 唤醒调度器，为新后缀启动 worker
	default:
	}
	return nil
}

// logDiff 输出本次热更新的变更摘要。
func (e *Engine) logDiff(old, new *Runtime, added, dropped []string) {
	attrs := []any{"域名数", len(new.Cfg.Domains), "新增", len(added), "移除", len(dropped)}
	if len(added) > 0 {
		attrs = append(attrs, "added", added)
	}
	if len(dropped) > 0 {
		attrs = append(attrs, "dropped", dropped)
	}
	if old != nil {
		oq, nq := old.Cfg.Query, new.Cfg.Query
		if oq.SleepMin != nq.SleepMin || oq.SleepMax != nq.SleepMax {
			attrs = append(attrs, "休眠区间", fmt.Sprintf("%s~%s", nq.SleepMin, nq.SleepMax))
		}
		if oq.Timeout != nq.Timeout || oq.Retries != nq.Retries {
			attrs = append(attrs, "超时", nq.Timeout, "重试", nq.Retries)
		}
		if oq.Intervals != nq.Intervals {
			attrs = append(attrs, "检查间隔", fmt.Sprintf("赎回期 %s / 待删除 %s / 可注册 %s",
				nq.Intervals.RedemptionPeriod, nq.Intervals.PendingDelete, nq.Intervals.Available))
		}
		if old.Cfg.RemoveWhen != new.Cfg.RemoveWhen {
			attrs = append(attrs, "remove_when", new.Cfg.RemoveWhen)
		}
		if old.Cfg.LogLevel != new.Cfg.LogLevel {
			attrs = append(attrs, "日志级别", new.Cfg.LogLevel)
		}
		var oldEnd, newEnd string
		if old.Notifier != nil {
			oldEnd = old.Notifier.endpoint
		}
		if new.Notifier != nil {
			newEnd = new.Notifier.endpoint
		}
		if oldEnd != newEnd {
			attrs = append(attrs, "推送", new.Notifier.Enabled())
		}
	}
	e.log.Info("配置已热更新", attrs...)
	if len(new.Cfg.Domains) == 0 {
		e.log.Warn("配置中 domains 为空，暂停监控（等待下次配置更新）")
	}
}

// fileDigest 返回配置文件内容的 sha256，用于判断是否变更。
func (e *Engine) fileDigest() (string, error) {
	raw, err := os.ReadFile(e.path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
