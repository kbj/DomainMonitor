package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

var version = "1.1.0"

func main() {
	cfgPath := flag.String("c", "config.yaml", "配置文件路径")
	showVersion := flag.Bool("v", false, "显示版本号")
	flag.Parse()

	if *showVersion {
		fmt.Println("DomainMonitor", version)
		return
	}
	args := flag.Args()
	switch {
	case len(args) == 0:
		run(*cfgPath)
	case args[0] == "check" && len(args) >= 2:
		runCheck(*cfgPath, args[1])
	default:
		fmt.Fprintln(os.Stderr, "用法:\n"+
			"  domainmonitor -c config.yaml              # 启动常驻监控（支持配置热更新）\n"+
			"  domainmonitor -c config.yaml check <域名>  # 手动查询一次(不推送、不写状态)\n"+
			"  domainmonitor -v                          # 显示版本")
		os.Exit(2)
	}
}

// parseLevel 解析日志级别（启动与热更新共用）。
func parseLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// newLogger 创建日志器；级别由 LevelVar 持有，热更新时可动态调整。
func newLogger(level *slog.LevelVar) *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "错误:", err)
	os.Exit(1)
}

// run 启动常驻监控。
func run(cfgPath string) {
	cfg, err := LoadConfig(cfgPath, true)
	if err != nil {
		fatal(err)
	}
	levelVar := new(slog.LevelVar)
	levelVar.Set(parseLevel(cfg.LogLevel))
	logger := newLogger(levelVar)

	state, err := LoadState(cfg.StateFile, cfg.Domains, logger)
	if err != nil {
		fatal(err)
	}
	rt, err := buildRuntime(cfg, logger)
	if err != nil {
		fatal(err)
	}
	engine := NewEngine(cfgPath, rt, state, logger, levelVar)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if cfg.Reload.IsEnabled() {
		go engine.watchConfig(ctx, cfg.Reload.Interval.D())
	}
	logger.Info("DomainMonitor 启动", "版本", version, "配置", cfgPath,
		"监控域名", len(cfg.Domains), "状态文件", cfg.StateFile,
		"推送", rt.Notifier.Enabled(),
		"热更新", map[bool]string{true: "已启用", false: "未启用"}[cfg.Reload.IsEnabled()])
	engine.Run(ctx)

	if err := state.Save(); err != nil {
		logger.Error("退出前保存状态失败", "err", err)
	}
	logger.Info("DomainMonitor 已退出")
}

// runCheck 手动查询一次，用于调试后缀配置（不推送、不写状态文件）。
func runCheck(cfgPath, domain string) {
	cfg, err := LoadConfig(cfgPath, false)
	if err != nil {
		fatal(err)
	}
	tld := cfg.TLDOf(domain)
	if tld == nil {
		fatal(fmt.Errorf("域名 %s 无法匹配配置中的任何后缀", domain))
	}
	checker, err := buildChecker(cfg, *tld)
	if err != nil {
		fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(),
		time.Duration(cfg.Query.Retries+1)*cfg.Query.Timeout.D()+30*time.Second)
	defer cancel()

	res := checker.Check(ctx, domain)
	fmt.Printf("域名: %s\n后缀: %s\n状态: %s\n通道: %s\n依据: %s\n",
		domain, tld.Suffix, res.Status, res.Channel, res.Detail)
	if res.Status == StatusError {
		os.Exit(1)
	}
}
