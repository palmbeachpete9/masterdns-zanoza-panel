package dnscache

import (
	"bytes"
	"testing"
	"time"
)

// N02 — a ready entry expires on an absolute TTL from insertion; a recent hit
// must NOT extend it.
func TestReadyEntryExpiresAbsolutely(t *testing.T) {
	s := New(16, 10*time.Second, time.Second)
	t0 := time.Now()
	e := &Entry{Status: StatusReady, CreatedAt: t0, LastUsedAt: t0.Add(9 * time.Second)}

	if s.isExpired(e, t0.Add(9*time.Second)) {
		t.Fatal("entry should still be valid at 9s")
	}
	// Even though it was just used at 9s, it must be expired at 11s (> TTL from
	// CreatedAt) — a hit cannot keep it alive forever.
	if !s.isExpired(e, t0.Add(11*time.Second)) {
		t.Fatal("entry extended past TTL by recent use (N02)")
	}
}

// F22 — the full-query key ignores the transaction ID but distinguishes any
// other query-shape difference (e.g. EDNS/DNSSEC bytes).
func TestBuildKeyFromQueryShape(t *testing.T) {
	q1 := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1, 'a', 0x00}
	q2 := append([]byte(nil), q1...)
	q2[0], q2[1] = 0xAB, 0xCD // different transaction ID only
	if BuildKeyFromQuery(q1) != BuildKeyFromQuery(q2) {
		t.Fatal("transaction ID must not affect the cache key")
	}

	q3 := append([]byte(nil), q1...)
	q3[len(q3)-1] ^= 0x01 // change a query-shape byte (e.g. EDNS/flags)
	if BuildKeyFromQuery(q1) == BuildKeyFromQuery(q3) {
		t.Fatal("a query-shape change must change the cache key (F22)")
	}

	// Sanity: identical queries share a key.
	if !bytes.Equal([]byte(BuildKeyFromQuery(q1)), []byte(BuildKeyFromQuery(append([]byte(nil), q1...)))) {
		t.Fatal("identical queries must share a key")
	}
}
