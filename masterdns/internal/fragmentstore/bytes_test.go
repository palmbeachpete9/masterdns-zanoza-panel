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
