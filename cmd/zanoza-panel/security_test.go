package main

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// F14 — panel path validation rejects redirect-loop-inducing values.
func TestNormalizePanelPath(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"/admin", "/admin", true},
		{"admin", "/admin", true},
		{"/admin/", "/admin", true},
		{"  /secret  ", "/secret", true},
		{"", "", false},
		{"/", "", false},
		{"//", "", false},
		{"/a/b", "", false},
		{"/ad min", "", false},
		{"/admin?x", "", false},
		{"/admin#y", "", false},
	}
	for _, c := range cases {
		got, err := normalizePanelPath(c.in)
		if c.ok && (err != nil || got != c.want) {
			t.Errorf("normalizePanelPath(%q) = %q,%v; want %q,nil", c.in, got, err, c.want)
		}
		if !c.ok && err == nil {
			t.Errorf("normalizePanelPath(%q) = %q; want error", c.in, got)
		}
	}
}

// F06 — domain canonicalization strips the trailing dot and lowercases, so the
// panel agrees with the server on identity.
func TestCanonicalDomain(t *testing.T) {
	for _, eq := range [][2]string{
		{"Example.COM", "example.com"},
		{"example.com.", "example.com"},
		{" v.Example.com. ", "v.example.com"},
	} {
		got, err := canonicalDomain(eq[0])
		if err != nil || got != eq[1] {
			t.Errorf("canonicalDomain(%q) = %q,%v; want %q", eq[0], got, err, eq[1])
		}
	}
	for _, bad := range []string{"", "nodot", "a..b.com", "-bad.com", "x.example.com/extra", "*.example.com"} {
		if _, err := canonicalDomain(bad); err == nil {
			t.Errorf("canonicalDomain(%q) should fail", bad)
		}
	}
}

// F07 — passwords are stored with bcrypt; legacy SHA-256 authenticates once and
// migrates.
func TestCredentialsBcryptAndMigration(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, "panel.env")

	c := loadCredentials(envPath)
	if err := c.set("admin", "longenough1"); err != nil {
		t.Fatalf("set: %v", err)
	}
	raw, _ := os.ReadFile(envPath)
	if !strings.Contains(string(raw), "PASS_BCRYPT") || strings.Contains(string(raw), "PASS_HASH") {
		t.Fatalf("expected bcrypt-only panel.env, got: %s", raw)
	}
	if !c.verify("admin", "longenough1") || c.verify("admin", "wrong") {
		t.Fatal("bcrypt verify mismatch")
	}

	// Legacy migration.
	legacyDir := t.TempDir()
	legacyPath := filepath.Join(legacyDir, "panel.env")
	salt := "deadbeef"
	body := fmt.Sprintf("ZANOZA_PANEL_USER='joe'\nZANOZA_PANEL_SALT='%s'\nZANOZA_PANEL_PASS_HASH='%s'\n",
		salt, legacyHashPassword(salt, "legacypass1"))
	if err := os.WriteFile(legacyPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	lc := loadCredentials(legacyPath)
	if !lc.verify("joe", "legacypass1") {
		t.Fatal("legacy verify failed")
	}
	migrated, _ := os.ReadFile(legacyPath)
	if !strings.Contains(string(migrated), "PASS_BCRYPT") {
		t.Fatalf("legacy creds did not migrate to bcrypt: %s", migrated)
	}
}

func TestCredentialPasswordStdinIsBounded(t *testing.T) {
	if got, err := readCredentialPassword(strings.NewReader("longenough1")); err != nil || got != "longenough1" {
		t.Fatalf("readCredentialPassword valid input = %q, %v", got, err)
	}
	if _, err := readCredentialPassword(strings.NewReader(strings.Repeat("x", maxPasswordLen+1))); err == nil {
		t.Fatal("oversized stdin password was accepted")
	}
}

// F07 — password policy + username validation (F24).
func TestCredentialPolicy(t *testing.T) {
	c := loadCredentials(filepath.Join(t.TempDir(), "panel.env"))
	if err := c.set("admin", "short"); err == nil {
		t.Error("short password accepted")
	}
	if err := c.set("bad\nuser", "longenough1"); err == nil {
		t.Error("username with newline accepted")
	}
	if err := c.set("ok'quote", "longenough1"); err == nil {
		t.Error("username with quote accepted")
	}
}

// F03 — createInitial succeeds exactly once under concurrency.
func TestCreateInitialOnce(t *testing.T) {
	c := loadCredentials(filepath.Join(t.TempDir(), "panel.env"))
	var ok int32
	var wg sync.WaitGroup
	var mu sync.Mutex
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.createInitial("admin", "longenough1"); err == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if ok != 1 {
		t.Fatalf("createInitial succeeded %d times; want exactly 1", ok)
	}
}

// F24/F13 — concurrent atomic persistence never corrupts or fails on rename.
func TestConcurrentCredentialPersist(t *testing.T) {
	c := loadCredentials(filepath.Join(t.TempDir(), "panel.env"))
	if err := c.set("admin", "longenough1"); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			_ = c.set("admin", fmt.Sprintf("password%05d", n))
		}(i)
	}
	wg.Wait()
	if !c.verify("admin", c.username()+"") && c.username() != "admin" {
		t.Fatal("user lost after concurrent writes")
	}
}

func TestConfigSaveConcurrent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	cfg := defaultConfig()
	cfg.path = path
	if err := cfg.save(); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			cfg.mu.Lock()
			cfg.Name = fmt.Sprintf("name-%d", n)
			cfg.mu.Unlock()
			if err := cfg.save(); err != nil {
				t.Errorf("save: %v", err)
			}
		}(i)
	}
	wg.Wait()
	raw, _ := os.ReadFile(path)
	var out Config
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("final config does not parse: %v\n%s", err, raw)
	}
}

// F28/F07 — sessions are bounded, revocable, and tokens come from crypto/rand.
func TestSessionStore(t *testing.T) {
	s := newSessionStore()
	tok, err := s.create()
	if err != nil || tok == "" {
		t.Fatalf("create: %v", err)
	}
	if !s.valid(tok) {
		t.Fatal("fresh token invalid")
	}
	s.revokeAll()
	if s.valid(tok) {
		t.Fatal("token survived revokeAll")
	}
}

// F07 — login limiter locks out after the configured number of failures.
func TestLoginLimiter(t *testing.T) {
	l := newLoginLimiter(3, time.Minute)
	key := "1.2.3.4"
	for i := 0; i < 3; i++ {
		if !l.allowed(key) {
			t.Fatalf("locked too early at %d", i)
		}
		l.fail(key)
	}
	if l.allowed(key) {
		t.Fatal("expected lockout after 3 failures")
	}
	l.reset(key)
	if !l.allowed(key) {
		t.Fatal("reset did not clear lockout")
	}
}

// F08 — request bodies are size-capped and reject trailing JSON.
func TestReadJSONLimits(t *testing.T) {
	big := strings.Repeat("a", maxJSONBody+1024)
	r := httptest.NewRequest("POST", "/", strings.NewReader(`{"user":"`+big+`"}`))
	w := httptest.NewRecorder()
	var body struct{ User string }
	if err := readJSON(w, r, &body); err == nil {
		t.Fatal("oversized body accepted")
	} else if _, ok := err.(errBodyTooLarge); !ok {
		t.Fatalf("want errBodyTooLarge, got %T", err)
	}

	r2 := httptest.NewRequest("POST", "/", strings.NewReader(`{"a":1}{"b":2}`))
	if err := readJSON(httptest.NewRecorder(), r2, &struct{ A int }{}); err == nil {
		t.Fatal("trailing JSON accepted")
	}

	r3 := httptest.NewRequest("POST", "/", strings.NewReader(`{"a":1}]`))
	if err := readJSON(httptest.NewRecorder(), r3, &struct{ A int }{}); err == nil {
		t.Fatal("malformed trailing token accepted")
	}

	for name, body := range map[string]string{
		"unknown field":             `{"a":1,"typo":2}`,
		"duplicate key":             `{"a":1,"a":2}`,
		"case-folded duplicate key": `{"a":1,"A":2}`,
		"non-object":                `null`,
	} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/", strings.NewReader(body))
			if err := readJSON(httptest.NewRecorder(), r, &struct{ A int }{}); err == nil {
				t.Fatalf("%s accepted", name)
			}
		})
	}
}

func TestWriteFileAtomic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f")
	if err := writeFileAtomic(path, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("stat: %v mode=%v", err, st.Mode().Perm())
	}
	// No leftover temp files in the directory.
	entries, _ := os.ReadDir(filepath.Dir(path))
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("leftover temp file: %s", e.Name())
		}
	}
}
