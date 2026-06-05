package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Credentials are stored hashed in panel.env:
//
//	ZANOZA_PANEL_USER='admin'
//	ZANOZA_PANEL_SALT='<hex>'
//	ZANOZA_PANEL_PASS_HASH='<hex sha256(salt:password)>'
type credentials struct {
	mu       sync.RWMutex
	envPath  string
	user     string
	salt     string
	passHash string
}

func loadCredentials(envPath string) *credentials {
	c := &credentials{envPath: envPath}
	raw, err := os.ReadFile(envPath)
	if err != nil {
		return c
	}
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		val = strings.Trim(strings.TrimSpace(val), "'\"")
		switch strings.TrimSpace(key) {
		case "ZANOZA_PANEL_USER":
			c.user = val
		case "ZANOZA_PANEL_SALT":
			c.salt = val
		case "ZANOZA_PANEL_PASS_HASH":
			c.passHash = val
		}
	}
	return c
}

func hashPassword(salt, password string) string {
	sum := sha256.Sum256([]byte(salt + ":" + password))
	return hex.EncodeToString(sum[:])
}

func (c *credentials) setupRequired() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.user == "" || c.passHash == ""
}

func (c *credentials) set(user, password string) error {
	if user == "" {
		return fmt.Errorf("логин обязателен")
	}
	if len(password) < 4 {
		return fmt.Errorf("пароль слишком короткий")
	}
	salt := randomToken(16)
	c.mu.Lock()
	c.user = user
	c.salt = salt
	c.passHash = hashPassword(salt, password)
	c.mu.Unlock()
	return c.persist()
}

func (c *credentials) verify(user, password string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.user == "" || c.passHash == "" {
		return false
	}
	userOK := subtle.ConstantTimeCompare([]byte(user), []byte(c.user)) == 1
	passOK := subtle.ConstantTimeCompare([]byte(hashPassword(c.salt, password)), []byte(c.passHash)) == 1
	return userOK && passOK
}

func (c *credentials) username() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.user
}

func (c *credentials) persist() error {
	c.mu.RLock()
	body := fmt.Sprintf(
		"ZANOZA_PANEL_USER='%s'\nZANOZA_PANEL_SALT='%s'\nZANOZA_PANEL_PASS_HASH='%s'\n",
		c.user, c.salt, c.passHash,
	)
	path := c.envPath
	c.mu.RUnlock()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(body), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

type sessionStore struct {
	mu       sync.Mutex
	sessions map[string]time.Time
	ttl      time.Duration
}

func newSessionStore() *sessionStore {
	return &sessionStore{sessions: map[string]time.Time{}, ttl: 12 * time.Hour}
}

func (s *sessionStore) create() string {
	token := randomToken(32)
	s.mu.Lock()
	s.sessions[token] = time.Now().Add(s.ttl)
	s.mu.Unlock()
	return token
}

func (s *sessionStore) valid(token string) bool {
	if token == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.sessions[token]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(s.sessions, token)
		return false
	}
	return true
}

func (s *sessionStore) revoke(token string) {
	s.mu.Lock()
	delete(s.sessions, token)
	s.mu.Unlock()
}

func randomToken(nBytes int) string {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}
