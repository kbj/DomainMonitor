package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"sync"
	"time"
)

const (
	stateVersion = 1
	maxHistory   = 10 // 每个域名保留的状态变化历史条数
)

// HistoryEntry 一次状态变化记录。
type HistoryEntry struct {
	At      time.Time `json:"at"`
	From    string    `json:"from"`
	To      string    `json:"to"`
	Channel string    `json:"channel,omitempty"`
	Detail  string    `json:"detail,omitempty"`
}

// DomainState 单个域名的监控状态。
type DomainState struct {
	Status      string         `json:"status"` // pending_delete / available / registered
	AddedAt     time.Time      `json:"added_at"`
	LastChecked time.Time      `json:"last_checked,omitempty"`
	Removed     bool           `json:"removed"` // true = 已移出监控列表
	RemovedAt   time.Time      `json:"removed_at,omitempty"`
	History     []HistoryEntry `json:"history,omitempty"`
}

type stateFileData struct {
	Version int                     `json:"version"`
	Domains map[string]*DomainState `json:"domains"`
}

// StateStore 状态文件 state.json 的内存视图与读写。
// 多个后缀 goroutine 会并发调用，所有方法均加锁；文件写入采用 tmp+rename 原子替换。
type StateStore struct {
	mu   sync.Mutex
	path string
	data stateFileData
}

// LoadState 加载状态文件并按当前配置补齐/清理条目。
// 新出现的域名以 pending_delete 作为初始状态（工具的前提假设）。
func LoadState(path string, domains []string, logger *slog.Logger) (*StateStore, error) {
	st := &StateStore{
		path: path,
		data: stateFileData{Version: stateVersion, Domains: map[string]*DomainState{}},
	}
	if raw, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(raw, &st.data); err != nil {
			return nil, fmt.Errorf("解析状态文件失败: %w", err)
		}
		if st.data.Domains == nil {
			st.data.Domains = map[string]*DomainState{}
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("读取状态文件失败: %w", err)
	}

	added, dropped := st.Sync(domains, time.Now())
	for _, d := range added {
		logger.Info("新增监控域名", "domain", d, "初始状态", string(StatusPendingDelete))
	}
	for _, d := range dropped {
		logger.Debug("清理不再监控的域名状态", "domain", d)
	}
	return st, nil
}

// Sync 按最新配置补齐新增域名、清理已移除域名，返回 (新增, 移除) 列表。
// 启动加载与配置热更新共用；新增域名以 pending_delete 作为初始状态（工具的前提假设）。
func (s *StateStore) Sync(domains []string, now time.Time) (added, dropped []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	inCfg := make(map[string]bool, len(domains))
	for _, d := range domains {
		inCfg[d] = true
	}
	for d := range s.data.Domains {
		if !inCfg[d] {
			delete(s.data.Domains, d)
			dropped = append(dropped, d)
		}
	}
	for _, d := range domains {
		if _, ok := s.data.Domains[d]; !ok {
			s.data.Domains[d] = &DomainState{Status: string(StatusPendingDelete), AddedAt: now}
			added = append(added, d)
		}
	}
	sort.Strings(dropped)
	if len(added) > 0 || len(dropped) > 0 {
		_ = s.save()
	}
	return added, dropped
}

// Get 返回域名状态的副本。
func (s *StateStore) Get(domain string) (DomainState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ds, ok := s.data.Domains[domain]
	if !ok {
		return DomainState{}, false
	}
	return *ds, true
}

// Record 记录一次查询结果，返回 (状态是否变化, 旧状态)。
func (s *StateStore) Record(domain string, status Status, channel, detail string, now time.Time) (bool, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ds, ok := s.data.Domains[domain]
	if !ok {
		ds = &DomainState{Status: string(StatusPendingDelete), AddedAt: now}
		s.data.Domains[domain] = ds
	}
	prev := ds.Status
	changed := prev != string(status)
	ds.LastChecked = now
	if changed {
		ds.Status = string(status)
		ds.History = append(ds.History, HistoryEntry{
			At: now, From: prev, To: string(status), Channel: channel, Detail: detail,
		})
		if len(ds.History) > maxHistory {
			ds.History = ds.History[len(ds.History)-maxHistory:]
		}
	}
	_ = s.save()
	return changed, prev
}

// Touch 仅更新 last_checked（查询失败时也计入最小检查间隔）。
func (s *StateStore) Touch(domain string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ds, ok := s.data.Domains[domain]; ok {
		ds.LastChecked = now
		_ = s.save()
	}
}

// MarkRemoved 将域名标记为已移出监控列表。
func (s *StateStore) MarkRemoved(domain string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ds, ok := s.data.Domains[domain]
	if !ok {
		return nil
	}
	ds.Removed = true
	ds.RemovedAt = time.Now()
	return s.save()
}

// Save 强制落盘（进程退出前调用）。
func (s *StateStore) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.save()
}

// save 必须在持有锁的情况下调用：tmp + rename 原子写入。
func (s *StateStore) save() error {
	data, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("写入状态文件失败: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("替换状态文件失败: %w", err)
	}
	return nil
}
