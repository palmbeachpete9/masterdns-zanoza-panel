package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// R-02/V4-03 — first-run setup must reject cross-origin, different-scheme, and
// non-JSON requests, AND require the one-time bootstrap token. Even an exact
// same-origin JSON request (e.g. a DNS-rebinding attempt) is rejected without
// the locally-printed token.
func TestSetupOriginContentTypeAndToken(t *testing.T) {
	mk := func(origin, ctype, token string) (*httptest.ResponseRecorder, *server) {
		s := newTestServer(t) // fresh creds dir => setup required, useTLS=false
		body := fmt.Sprintf(`{"user":"adminuser","password":"longenough1","token":%q}`, token)
		r := httptest.NewRequest(http.MethodPost, "http://panel.local/admin/api/auth/setup", strings.NewReader(body))
		r.Host = "panel.local"
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		r.Header.Set("Content-Type", ctype)
		w := httptest.NewRecorder()
		s.handleAuthSetup(w, r)
		return w, s
	}

	if w, s := mk("https://evil.example", "application/json", s2tok(t)); w.Code != http.StatusForbidden || s.creds.setupRequired() == false {
		t.Fatalf("cross-origin setup = %d (want 403, setup still required)", w.Code)
	}
	if w, _ := mk("http://panel.local", "text/plain", s2tok(t)); w.Code != http.StatusForbidden {
		t.Fatalf("text/plain setup = %d, want 403", w.Code)
	}
	if w, _ := mk("https://panel.local", "application/json", s2tok(t)); w.Code != http.StatusForbidden {
		t.Fatalf("different-scheme setup = %d, want 403 (panel is http)", w.Code)
	}
	if w, _ := mk("", "application/json", s2tok(t)); w.Code != http.StatusForbidden {
		t.Fatalf("missing-origin browser setup = %d, want 403", w.Code)
	}
	// Same-origin JSON but WRONG token (DNS-rebinding without the secret) -> 403.
	if w, _ := mk("http://panel.local", "application/json", "wrong-token"); w.Code != http.StatusForbidden {
		t.Fatalf("same-origin without correct token = %d, want 403 (V4-03)", w.Code)
	}

	// Same-origin JSON WITH the correct token -> 200, and the token is consumed.
	s := newTestServer(t)
	tok := s.setup.logToken()
	body := fmt.Sprintf(`{"user":"adminuser","password":"longenough1","token":%q}`, tok)
	r := httptest.NewRequest(http.MethodPost, "http://panel.local/admin/api/auth/setup", strings.NewReader(body))
	r.Host = "panel.local"
	r.Header.Set("Origin", "http://panel.local")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handleAuthSetup(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("valid token setup = %d, want 200", w.Code)
	}
	if s.setup.required() {
		t.Fatal("token must be consumed after successful setup (V4-03)")
	}
}

// s2tok just yields a fresh (unrelated) token for negative cases where the value
// will never match the per-call server's token.
func s2tok(t *testing.T) string { t.Helper(); return "irrelevant-token" }

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

// V4-06 — a failed keyring write must not advance the desired digest and must
// record the error; a later matching applied marker reconciles a stale error.
func TestApplyStateTruthful(t *testing.T) {
	// Failed write: runtimeDir parent is a regular file, so MkdirAll fails.
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	broken := newServerManager(filepath.Join(blocker, "sub"))
	if err := broken.writeKeyring([]Instance{{Domain: "v.example.com", Key: "k", Method: 5}}); err == nil {
		t.Fatal("expected keyring write to fail")
	}
	if broken.desiredDigest != "" {
		t.Fatal("failed write advanced desired digest (V4-06)")
	}
	if broken.state().ApplyError == "" {
		t.Fatal("apply error not recorded in state (V4-06)")
	}

	// Success then stale-error reconciliation via a matching applied marker.
	m := newServerManager(t.TempDir())
	if err := m.writeKeyring([]Instance{{Domain: "v.example.com", Key: "k", Method: 5}}); err != nil {
		t.Fatal(err)
	}
	m.lastApplyErr = "stale transient error"
	m.cmd = &exec.Cmd{}
	m.pid = 1
	if err := writeTestAppliedMarker(m.keyringPath, m.desiredDigest, m.desiredGen); err != nil {
		t.Fatal(err)
	}
	if st := m.state(); st.ApplyError != "" {
		t.Fatalf("stale error not reconciled after matching ack: %q (V4-06)", st.ApplyError)
	}
}
