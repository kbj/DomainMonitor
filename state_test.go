package main

import (
	"path/filepath"
	"testing"
	"time"
)

func TestStateSync(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	log := quietLogger()

	st, err := LoadState(path, []string{"a.com", "b.com"}, log)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := st.Get("a.com"); !ok {
		t.Fatal("a.com 应存在")
	}

	added, dropped := st.Sync([]string{"b.com", "c.net"}, time.Now())
	if len(added) != 1 || added[0] != "c.net" {
		t.Errorf("added = %v, 期望 [c.net]", added)
	}
	if len(dropped) != 1 || dropped[0] != "a.com" {
		t.Errorf("dropped = %v, 期望 [a.com]", dropped)
	}
	if _, ok := st.Get("a.com"); ok {
		t.Error("a.com 状态应被清理")
	}

	// 幂等：无变化时不应报告 diff
	added2, dropped2 := st.Sync([]string{"b.com", "c.net"}, time.Now())
	if len(added2) != 0 || len(dropped2) != 0 {
		t.Errorf("重复 Sync 不应有变化: added=%v dropped=%v", added2, dropped2)
	}

	// 重新加载：已有状态必须保留（不能重置为 pending_delete）
	if err := st.MarkRemoved("b.com"); err != nil {
		t.Fatal(err)
	}
	st2, err := LoadState(path, []string{"b.com", "c.net"}, log)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := st2.Get("b.com")
	if !ok {
		t.Fatal("b.com 应保留")
	}
	if !got.Removed {
		t.Error("b.com 的 removed 标记应被保留")
	}
}
