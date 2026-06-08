package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// F13 — a failed persistence must leave live in-memory state unchanged.
func TestCommitPersistenceFailureLeavesLiveState(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := defaultConfig()
	cfg.Name = "original"
	// Parent of the config path is a regular file, so MkdirAll/write fails.
	cfg.path = filepath.Join(blocker, "sub", "config.json")

	err := cfg.commit(func(work *Config) error {
		work.Name = "uncommitted"
		return nil
	})
	if err == nil {
		t.Fatal("expected persistence failure")
	}
	if got := cfg.Meta().Name; got != "original" {
		t.Fatalf("failed persistence published live state: got %q, want %q", got, "original")
	}
	if cfg.Generation() != 0 {
		t.Fatalf("generation advanced on failed commit: %d", cfg.Generation())
	}
}

// F13 — a successful commit persists then publishes and bumps the generation.
func TestCommitSuccessPersistsAndPublishes(t *testing.T) {
	cfg := defaultConfig()
	cfg.path = filepath.Join(t.TempDir(), "config.json")
	if err := cfg.commit(func(work *Config) error { work.Name = "renamed"; return nil }); err != nil {
		t.Fatal(err)
	}
	if cfg.Meta().Name != "renamed" || cfg.Generation() != 1 {
		t.Fatalf("commit did not publish: name=%q gen=%d", cfg.Meta().Name, cfg.Generation())
	}
	reloaded, err := loadConfig(cfg.path)
	if err != nil || reloaded.Name != "renamed" {
		t.Fatalf("persisted config mismatch: %v name=%q", err, reloaded.Name)
	}
}

// F06 — a config with a canonical-collision domain using a non-AEAD method must
// fail to load (fail closed).
func TestLoadConfigRejectsCanonicalCollision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	// "v.example.com" (XOR) and "V.Example.com." (XOR) canonicalize to one
	// domain with two non-AEAD keys — must be rejected.
	body := `{"version":1,"name":"x","panel_addr":"127.0.0.1","panel_port":8443,"panel_path":"/admin","instances":[
		{"id":"a","domain":"v.example.com","key":"k1","method":1,"created_at":"t"},
		{"id":"b","domain":"V.Example.com.","key":"k2","method":1,"created_at":"t"}
	]}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil {
		t.Fatal("expected loadConfig to reject canonical collision with non-AEAD keys")
	}
}

func newTestServer(t *testing.T) *server {
	t.Helper()
	return &server{
		cfg:      defaultConfig(),
		creds:    loadCredentials(filepath.Join(t.TempDir(), "panel.env")),
		sessions: newSessionStore(),
		limiter:  newLoginLimiter(8, time.Minute),
	}
}

// N04 — logout must reject non-POST (a top-level GET must not revoke a session).
func TestLogoutRejectsGET(t *testing.T) {
	s := newTestServer(t)
	r := httptest.NewRequest(http.MethodGet, "/admin/api/auth/logout", nil)
	w := httptest.NewRecorder()
	s.handleAuthLogout(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET logout returned %d, want 405", w.Code)
	}
}

// N04 — cross-origin state-changing requests are rejected by requireAuth.
func TestRequireAuthRejectsCrossOrigin(t *testing.T) {
	s := newTestServer(t)
	tok, err := s.sessions.create()
	if err != nil {
		t.Fatal(err)
	}

	mk := func(origin string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "http://panel.local/admin/api/server/restart", nil)
		r.Host = "panel.local"
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: tok})
		w := httptest.NewRecorder()
		called := false
		s.requireAuth(w, r, func(http.ResponseWriter, *http.Request) { called = true })
		if origin == "http://evil.example" && called {
			t.Fatal("cross-origin mutation reached the handler")
		}
		return w
	}

	if w := mk("http://evil.example"); w.Code != http.StatusForbidden {
		t.Fatalf("cross-origin POST returned %d, want 403", w.Code)
	}
	if w := mk("http://panel.local"); w.Code == http.StatusForbidden {
		t.Fatal("same-origin POST was rejected")
	}
	if w := mk(""); w.Code == http.StatusForbidden {
		t.Fatal("no-Origin request (non-browser) was rejected")
	}
}
