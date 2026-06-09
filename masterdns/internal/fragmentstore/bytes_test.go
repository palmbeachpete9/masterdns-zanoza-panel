package fragmentstore

import (
	"testing"
	"time"
)

// F18 — byte accounting stays balanced and oversized fragments are rejected.
func TestStoreByteAccountingBalanced(t *testing.T) {
	s := New[int](16)
	now := time.Now()

	// An oversized single fragment is rejected before retaining any bytes.
	big := make([]byte, defaultMaxFragmentBytes+1)
	if out, done, _ := s.Collect(1, big, 0, 2, now, time.Minute); done || out != nil {
		t.Fatal("oversized fragment should be rejected")
	}
	s.mu.Lock()
	b0 := s.bytes
	s.mu.Unlock()
	if b0 != 0 {
		t.Fatalf("oversized fragment retained %d bytes", b0)
	}

	// A normal 2-fragment assembly completes, and retained bytes return to 0.
	s.Collect(2, []byte("AB"), 0, 2, now, time.Minute)
	s.mu.Lock()
	mid := s.bytes
	s.mu.Unlock()
	if mid != 2 {
		t.Fatalf("partial retained %d bytes, want 2", mid)
	}
	out, done, _ := s.Collect(2, []byte("CD"), 1, 2, now, time.Minute)
	if !done || string(out) != "ABCD" {
		t.Fatalf("assembly failed: %q done=%v", out, done)
	}
	s.mu.Lock()
	b1 := s.bytes
	s.mu.Unlock()
	if b1 != 0 {
		t.Fatalf("retained bytes after completion = %d, want 0", b1)
	}
}

// F18 — replacing a fragment with a larger payload keeps accounting exact and
// purge returns the byte budget to zero.
func TestStoreByteAccountingOnReplaceAndPurge(t *testing.T) {
	s := New[int](16)
	now := time.Now()
	s.Collect(1, []byte("A"), 0, 3, now, time.Minute)
	s.Collect(1, []byte("BBB"), 0, 3, now, time.Minute) // replace slot 0 (1 -> 3 bytes)
	s.mu.Lock()
	got := s.bytes
	s.mu.Unlock()
	if got != 3 {
		t.Fatalf("after replace retained %d bytes, want 3", got)
	}
	s.Purge(now.Add(time.Hour), time.Minute) // everything expired
	s.mu.Lock()
	got = s.bytes
	s.mu.Unlock()
	if got != 0 {
		t.Fatalf("after purge retained %d bytes, want 0", got)
	}
}

// R-04 — a single-fragment completion on a key that has a partial multi-fragment
// entry must return that entry's bytes to the budget (no leak).
func TestSingleFragmentCompletionReturnsBytes(t *testing.T) {
	s := New[int](16)
	now := time.Now()
	s.Collect(1, []byte("12345678"), 0, 2, now, time.Minute) // partial, 8 bytes
	s.mu.Lock()
	b := s.bytes
	s.mu.Unlock()
	if b != 8 {
		t.Fatalf("partial bytes = %d, want 8", b)
	}
	s.Collect(1, []byte("x"), 0, 1, now, time.Minute) // single-fragment completion, same key
	s.mu.Lock()
	b = s.bytes
	s.mu.Unlock()
	if b != 0 {
		t.Fatalf("byte budget leaked after single-fragment completion: %d, want 0 (R-04)", b)
	}

	// Repeat many times: the budget must not accumulate a leak.
	for i := 0; i < 50000; i++ {
		s.Collect(2, make([]byte, 200), 0, 2, now, time.Minute)
		s.Collect(2, []byte("x"), 0, 1, now, time.Minute)
	}
	s.mu.Lock()
	b = s.bytes
	s.mu.Unlock()
	if b != 0 {
		t.Fatalf("accumulated byte leak: %d, want 0 (R-04)", b)
	}
}
