package fragmentstore

import (
	"testing"
	"time"
)

// F18 — a flood of unique keys must never grow the store beyond its capacity.
func TestStoreBoundedUnderKeyFlood(t *testing.T) {
	const capacity = 4
	s := New[int](capacity)
	now := time.Now()
	retention := time.Minute

	// Thousands of distinct partial reassemblies (2 fragments each, only the
	// first delivered so they stay partial).
	for i := 0; i < 5000; i++ {
		s.Collect(i, []byte{byte(i)}, 0, 2, now, retention)
		s.mu.Lock()
		if len(s.items) > capacity {
			s.mu.Unlock()
			t.Fatalf("partial map grew to %d > capacity %d", len(s.items), capacity)
		}
		s.mu.Unlock()
	}

	// Thousands of single-fragment completions create completion markers.
	for i := 0; i < 5000; i++ {
		s.Collect(100000+i, []byte{1}, 0, 1, now, retention)
		s.mu.Lock()
		if len(s.completed) > capacity {
			s.mu.Unlock()
			t.Fatalf("completed map grew to %d > capacity %d", len(s.completed), capacity)
		}
		s.mu.Unlock()
	}
}

// A complete 2-fragment message still reassembles correctly with the bounded store.
func TestStoreReassembles(t *testing.T) {
	s := New[int](8)
	now := time.Now()
	if _, done, _ := s.Collect(1, []byte("AB"), 0, 2, now, time.Minute); done {
		t.Fatal("completed too early")
	}
	out, done, _ := s.Collect(1, []byte("CD"), 1, 2, now, time.Minute)
	if !done || string(out) != "ABCD" {
		t.Fatalf("reassembly = %q done=%v; want ABCD true", out, done)
	}
}
