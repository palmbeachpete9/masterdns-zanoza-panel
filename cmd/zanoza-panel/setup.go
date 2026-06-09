package main

import (
	"crypto/subtle"
	"os"
	"path/filepath"
	"sync"
)

// setupGate enforces a one-time, high-entropy bootstrap token for the
// unauthenticated first-run setup endpoint. Same-origin checks alone cannot
// protect a loopback service from DNS rebinding, so the operator must read the
// token from the local console/log (or the 0600 token file) and supply it once
// (V4-03). Once consumed the token is cleared and the file removed.
type setupGate struct {
	mu    sync.Mutex
	token string // expected token; "" means setup is not (or no longer) open
	path  string
}

// newSetupGate creates (and persists) a fresh token when setup is required, or
// removes any stale token file otherwise.
func newSetupGate(configDir string, required bool) (*setupGate, error) {
	g := &setupGate{path: filepath.Join(configDir, "setup.token")}
	if !required {
		_ = os.Remove(g.path)
		return g, nil
	}
	tok, err := randomTokenStrict(32)
	if err != nil {
		return nil, err
	}
	if err := writeFileAtomic(g.path, []byte(tok+"\n"), 0o600); err != nil {
		return nil, err
	}
	g.token = tok
	return g, nil
}

func (g *setupGate) required() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.token != ""
}

// logToken returns the active token for one-time local display, or "".
func (g *setupGate) logToken() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.token
}

func (g *setupGate) check(provided string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.token == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(provided), []byte(g.token)) == 1
}

func (g *setupGate) consume() {
	g.mu.Lock()
	g.token = ""
	_ = os.Remove(g.path)
	g.mu.Unlock()
}
