package inflight

import (
	"testing"
	"time"
)

func TestStaleLeaderCannotResolveReplacementEntry(t *testing.T) {
	timeout := time.Second
	manager := New[string](timeout, timeout, nil)
	start := time.Now()

	stale, leader := manager.Acquire("key", start)
	if !leader {
		t.Fatal("first acquire was not leader")
	}
	replacement, leader := manager.Acquire("key", start.Add(timeout+time.Millisecond))
	if !leader || replacement == stale {
		t.Fatal("expired entry was not replaced")
	}

	if manager.Resolve("key", stale, "stale", true) {
		t.Fatal("stale leader resolved the replacement entry")
	}
	if manager.Resolve("key", replacement, "fresh", true) == false {
		t.Fatal("current leader could not resolve its entry")
	}
	if value, ok := manager.Wait(replacement, time.Second); !ok || value != "fresh" {
		t.Fatalf("replacement wait = %q, %v; want fresh, true", value, ok)
	}
}
