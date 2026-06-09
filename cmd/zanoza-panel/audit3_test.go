package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// R-02 — first-run setup must reject cross-origin, different-scheme, and
// non-JSON requests, and accept only an exact same-origin JSON request.
func TestSetupOriginAndContentType(t *testing.T) {
	body := `{"user":"adminuser","password":"longenough1"}`
	mk := func(origin, ctype string) *httptest.ResponseRecorder {
		s := newTestServer(t) // fresh creds dir => setup required, useTLS=false
		r := httptest.NewRequest(http.MethodPost, "http://panel.local/admin/api/auth/setup", strings.NewReader(body))
		r.Host = "panel.local"
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		r.Header.Set("Content-Type", ctype)
		w := httptest.NewRecorder()
		s.handleAuthSetup(w, r)
		return w
	}

	if w := mk("https://evil.example", "application/json"); w.Code != http.StatusForbidden {
		t.Fatalf("cross-origin setup = %d, want 403", w.Code)
	}
	if w := mk("http://panel.local", "text/plain"); w.Code != http.StatusForbidden {
		t.Fatalf("text/plain setup = %d, want 403", w.Code)
	}
	if w := mk("https://panel.local", "application/json"); w.Code != http.StatusForbidden {
		t.Fatalf("different-scheme setup = %d, want 403 (panel is http)", w.Code)
	}
	if w := mk("", "application/json"); w.Code != http.StatusForbidden {
		t.Fatalf("missing-origin browser setup = %d, want 403", w.Code)
	}
	if w := mk("http://panel.local", "application/json"); w.Code != http.StatusOK {
		t.Fatalf("exact same-origin JSON setup = %d, want 200", w.Code)
	}
}

// R-05 — duplicate or empty instance IDs must fail config load (they otherwise
// let two same-ID records hide each other and bypass multi-key validation).
func TestLoadConfigRejectsDuplicateAndEmptyIDs(t *testing.T) {
	write := func(t *testing.T, instances string) string {
		p := filepath.Join(t.TempDir(), "config.json")
		body := `{"version":1,"name":"x","panel_addr":"127.0.0.1","panel_port":8443,"panel_path":"/admin","instances":[` + instances + `]}`
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	// duplicate IDs, two same-domain non-AEAD keys (would bypass multi-key rule)
	dup := write(t, `{"id":"x","domain":"v.example.com","key":"k1","method":1,"created_at":"t"},{"id":"x","domain":"v.example.com","key":"k2","method":1,"created_at":"t"}`)
	if _, err := loadConfig(dup); err == nil {
		t.Fatal("expected duplicate-ID config to be rejected")
	}
	// empty ID
	empty := write(t, `{"id":"","domain":"v.example.com","key":"k1","method":5,"created_at":"t"}`)
	if _, err := loadConfig(empty); err == nil {
		t.Fatal("expected empty-ID config to be rejected")
	}
}

// V4-02 — unreadable/malformed credentials must fail closed (no first-run
// reopen); a genuinely absent file is first-run.
func TestCredentialsFailClosedOnMalformed(t *testing.T) {
	dir := t.TempDir()

	// Exists but incomplete (only a username) -> malformed -> fail closed.
	p := filepath.Join(dir, "panel.env")
	if err := os.WriteFile(p, []byte("ZANOZA_PANEL_USER='admin'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := loadCredentials(p)
	if c.loadError() == nil {
		t.Fatal("malformed creds must set loadError")
	}
	if c.setupRequired() {
		t.Fatal("malformed creds must NOT reopen setup (fail closed)")
	}

	// Absent file -> genuine first-run.
	c2 := loadCredentials(filepath.Join(dir, "absent.env"))
	if c2.loadError() != nil {
		t.Fatalf("absent file is first-run, not an error: %v", c2.loadError())
	}
	if !c2.setupRequired() {
		t.Fatal("absent creds => setup required")
	}
}
