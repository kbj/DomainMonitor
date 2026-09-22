package main

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration 支持 "0.5s" / "5s" / "500ms" 等格式的时长（yaml.v3 原生不解析 time.Duration）。
type Duration time.Duration

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var s string
	if err := node.Decode(&s); err != nil {
		return fmt.Errorf("时长需要写成字符串形式，如 \"0.5s\"、\"5s\"、\"500ms\"")
	}
	dur, err := time.ParseDuration(strings.TrimSpace(s))
	if err != nil {
		return fmt.Errorf("无效时长 %q（示例: 0.5s / 5s / 500ms）", s)
	}
	*d = Duration(dur)
	return nil
}

// D 转回标准库 time.Duration。
func (d Duration) D() time.Duration { return time.Duration(d) }

// String 支持 %s 格式化。
func (d Duration) String() string { return time.Duration(d).String() }

// IntervalConfig 按域名状态配置的最小检查间隔（0 表示不限制，即每轮都查）。
// 赎回期长达约 30 天且状态稳定，没必要高频查询；待删除期是关键窗口，保持快速节奏。
type IntervalConfig struct {
	RedemptionPeriod Duration `yaml:"redemption_period"` // 赎回期，默认 24h
	PendingDelete    Duration `yaml:"pending_delete"`    // 待删除，默认 0s（用 sleep_min~sleep_max 的快节奏）
	Available        Duration `yaml:"available"`         // 可注册后只需偶尔确认是否被注册，默认 30m
}

// QueryConfig 查询节奏相关配置。
type QueryConfig struct {
	SleepMin  Duration       `yaml:"sleep_min"` // 每次查询完成后随机休眠下限
	SleepMax  Duration       `yaml:"sleep_max"` // 随机休眠上限
	Timeout   Duration       `yaml:"timeout"`   // 单次 RDAP/WHOIS 查询超时
	Retries   int            `yaml:"retries"`   // 查询整体失败时的额外重试次数
	Intervals IntervalConfig `yaml:"intervals"` // 按状态分级的最小检查间隔
	Proxy     string         `yaml:"proxy"`     // RDAP 使用的 HTTP 代理
}

// ServerChanConfig Server酱³ 推送配置。
type ServerChanConfig struct {
	UID     string `yaml:"uid"` // 留空则尝试从 sendkey 中提取（sctp{uid}t...）
	SendKey string `yaml:"sendkey"`
	Tags    string `yaml:"tags"` // 推送标签，可选
}

// TLDConfig 单个后缀的查询地址配置。
type TLDConfig struct {
	Suffix          string   `yaml:"suffix"`
	Whois           string   `yaml:"whois"`                     // host 或 host:port
	RDAP            string   `yaml:"rdap"`                      // 支持 {domain} 占位符；留空则该后缀只用 WHOIS
	NotFoundMarkers []string `yaml:"notfound_marker,omitempty"` // 可选：覆盖该后缀 WHOIS "未注册" 判定关键词
}

// ReloadConfig 配置文件热更新配置。
type ReloadConfig struct {
	Enabled  *bool    `yaml:"enabled"`  // 是否监听配置变更，默认 true
	Interval Duration `yaml:"interval"` // 轮询间隔，默认 1s
}

// IsEnabled 报告热更新是否启用（未配置时默认启用）。
func (r ReloadConfig) IsEnabled() bool {
	if r.Enabled == nil {
		return true
	}
	return *r.Enabled
}

// Config 顶层配置。
type Config struct {
	Query             QueryConfig      `yaml:"query"`
	ServerChan        ServerChanConfig `yaml:"serverchan"`
	TLDs              []TLDConfig      `yaml:"tlds"`
	Domains           []string         `yaml:"domains"`
	RemoveWhen        string           `yaml:"remove_when"` // registered(默认) / available
	StateFile         string           `yaml:"state_file"`
	LogLevel          string           `yaml:"log_level"`
	NotifyOnError     bool             `yaml:"notify_on_error"`
	Reload            ReloadConfig     `yaml:"reload"`
	NotifyStageChange *bool            `yaml:"notify_stage_change"` // 阶段变化(赎回期↔待删除)是否推送，默认 true

	tldMap         map[string]*TLDConfig // suffix(小写) → 配置
	sortedSuffixes []string              // 按长度降序，用于最长后缀匹配
}

// StageChangeNotify 报告"赎回期 ↔ 待删除"这类阶段变化是否也推送（默认推送）。
func (c *Config) StageChangeNotify() bool {
	if c.NotifyStageChange == nil {
		return true
	}
	return *c.NotifyStageChange
}

// IntervalFor 返回某状态下该域名的最小检查间隔；0 表示每轮都查（节奏由 sleep_min~sleep_max 控制）。
// 间隔取自域名当前存储的状态，因此状态一变就会立刻切换节奏：
// 赎回期 → 待删除后会自动回到快速轮询。
func (c *Config) IntervalFor(s Status) time.Duration {
	switch s {
	case StatusRedemptionPeriod:
		return c.Query.Intervals.RedemptionPeriod.D()
	case StatusAvailable:
		return c.Query.Intervals.Available.D()
	default: // pending_delete（及未知状态）走快速节奏
		return c.Query.Intervals.PendingDelete.D()
	}
}

var (
	domainRe    = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)
	suffixRe    = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)
	whoisAddrRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.-]*(:\d{1,5})?$`)
)

// LoadConfig 读取并校验配置。strict=true 用于常驻监控（要求 domains 非空）；
// strict=false 用于 check 子命令（允许 domains 为空）。
func LoadConfig(path string, strict bool) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %w", err)
	}
	cfg := &Config{}
	if err := yaml.Unmarshal(raw, cfg); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %w", err)
	}
	cfg.applyDefaults()
	if err := cfg.validate(strict); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Query.SleepMin == 0 {
		c.Query.SleepMin = Duration(500 * time.Millisecond)
	}
	if c.Query.SleepMax == 0 {
		c.Query.SleepMax = Duration(5 * time.Second)
	}
	if c.Query.Timeout == 0 {
		c.Query.Timeout = Duration(10 * time.Second)
	}
	if c.Query.Retries == 0 {
		c.Query.Retries = 2
	}
	if c.RemoveWhen == "" {
		c.RemoveWhen = "registered"
	}
	if c.StateFile == "" {
		c.StateFile = "state.json"
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	if c.Reload.Interval == 0 {
		c.Reload.Interval = Duration(time.Second)
	}
	if c.Query.Intervals.RedemptionPeriod == 0 {
		c.Query.Intervals.RedemptionPeriod = Duration(24 * time.Hour)
	}
	if c.Query.Intervals.Available == 0 {
		c.Query.Intervals.Available = Duration(30 * time.Minute)
	}
}

func (c *Config) validate(strict bool) error {
	if c.Query.SleepMin.D() <= 0 {
		return fmt.Errorf("query.sleep_min 必须大于 0")
	}
	if c.Query.SleepMax.D() < c.Query.SleepMin.D() {
		return fmt.Errorf("query.sleep_max (%s) 不能小于 sleep_min (%s)", c.Query.SleepMax, c.Query.SleepMin)
	}
	if c.Query.Timeout.D() <= 0 {
		return fmt.Errorf("query.timeout 必须大于 0")
	}
	if c.Query.Retries < 0 {
		return fmt.Errorf("query.retries 不能为负数")
	}
	if c.Reload.Interval.D() < 100*time.Millisecond {
		return fmt.Errorf("reload.interval 不能小于 100ms")
	}
	if c.Query.Intervals.RedemptionPeriod.D() < 0 ||
		c.Query.Intervals.PendingDelete.D() < 0 ||
		c.Query.Intervals.Available.D() < 0 {
		return fmt.Errorf("query.intervals 不能为负数")
	}
	switch c.RemoveWhen {
	case "registered", "available":
	default:
		return fmt.Errorf("remove_when 只能是 registered 或 available，当前为 %q", c.RemoveWhen)
	}

	if len(c.TLDs) == 0 {
		return fmt.Errorf("tlds 不能为空")
	}
	c.tldMap = map[string]*TLDConfig{}
	for i := range c.TLDs {
		t := &c.TLDs[i]
		t.Suffix = strings.ToLower(strings.TrimSpace(t.Suffix))
		if t.Suffix == "" {
			return fmt.Errorf("tlds[%d].suffix 不能为空", i)
		}
		if !suffixRe.MatchString(t.Suffix) {
			return fmt.Errorf("tlds[%d].suffix 格式无效: %q", i, t.Suffix)
		}
		if _, dup := c.tldMap[t.Suffix]; dup {
			return fmt.Errorf("后缀 %q 重复配置", t.Suffix)
		}
		if t.Whois == "" && t.RDAP == "" {
			return fmt.Errorf("后缀 %q 的 whois 与 rdap 至少要配置一个", t.Suffix)
		}
		if t.Whois != "" && !whoisAddrRe.MatchString(t.Whois) {
			return fmt.Errorf("后缀 %q 的 whois 地址无效（应为 host 或 host:port）: %q", t.Suffix, t.Whois)
		}
		if t.RDAP != "" && !strings.HasPrefix(t.RDAP, "http://") && !strings.HasPrefix(t.RDAP, "https://") {
			return fmt.Errorf("后缀 %q 的 rdap 地址必须以 http(s):// 开头: %q", t.Suffix, t.RDAP)
		}
		c.tldMap[t.Suffix] = t
	}
	c.sortedSuffixes = make([]string, 0, len(c.tldMap))
	for s := range c.tldMap {
		c.sortedSuffixes = append(c.sortedSuffixes, s)
	}
	sort.Slice(c.sortedSuffixes, func(i, j int) bool {
		return len(c.sortedSuffixes[i]) > len(c.sortedSuffixes[j])
	})

	seen := map[string]bool{}
	for i, d := range c.Domains {
		d = strings.ToLower(strings.TrimSpace(d))
		c.Domains[i] = d
		if !domainRe.MatchString(d) {
			return fmt.Errorf("domains[%d] 域名格式无效（IDN 域名请写成 punycode）: %q", i, d)
		}
		if seen[d] {
			return fmt.Errorf("domains 中域名重复: %s", d)
		}
		seen[d] = true
		if c.TLDOf(d) == nil {
			return fmt.Errorf("domains[%d] (%s) 无法匹配 tlds 中配置的任何后缀", i, d)
		}
	}
	if strict && len(c.Domains) == 0 {
		return fmt.Errorf("domains 不能为空")
	}
	return nil
}

// TLDOf 按最长后缀匹配返回域名对应的 TLD 配置；无匹配或域名本身是后缀时返回 nil。
func (c *Config) TLDOf(domain string) *TLDConfig {
	d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	for _, s := range c.sortedSuffixes {
		if d == s {
			return nil
		}
		if strings.HasSuffix(d, "."+s) {
			return c.tldMap[s]
		}
	}
	return nil
}
