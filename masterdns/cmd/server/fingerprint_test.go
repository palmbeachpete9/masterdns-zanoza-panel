package main

import (
	"strings"
	"testing"
)

// V4-04 — the key fingerprint must never contain the key itself.
func TestKeyFingerprintHidesKey(t *testing.T) {
	key := "SUPER-SECRET-CANARY-KEY-1234567890"
	fp := keyFingerprint(key)
	if strings.Contains(fp, key) || strings.Contains(fp, "CANARY") {
		t.Fatalf("fingerprint leaks key: %q", fp)
	}
	if keyFingerprint("") != "none" {
		t.Fatal("empty key fingerprint should be 'none'")
	}
}
