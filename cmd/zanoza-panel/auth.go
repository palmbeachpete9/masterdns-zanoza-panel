package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Credentials are stored in panel.env. New installs use a memory-hard bcrypt
// hash:
//
//	ZANOZA_PANEL_USER='admin'
//	ZANOZA_PANEL_PASS_BCRYPT='$2a$...'
//
// Legacy installs used a single salted SHA-256 round:
//
//	ZANOZA_PANEL_SALT='<hex>'
//	ZANOZA_PANEL_PASS_HASH='<hex sha256(salt:password)>'
//
// Legacy credentials still authenticate once and are transparently migrated to
// bcrypt on the next successful login (F07).
type credentials struct {
	mu      sync.RWMutex
	envPath string
	user    string

	bcryptHash string // preferred
	legacySalt string // legacy SHA-256 migration only
	legacyHash string
}

const (
	minPasswordLen = 8
	maxPasswordLen = 72 // bcrypt input ceiling
	maxUsernameLen = 64
	bcryptCost     = 12
)

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
		case "ZANOZA_PANEL_PASS_BCRYPT":
			c.bcryptHash = val
		case "ZANOZA_PANEL_SALT":
			c.legacySalt = val
		case "ZANOZA_PANEL_PASS_HASH":
			c.legacyHash = val
		}
	}
	return c
}

func legacyHashPassword(salt, password string) string {
	sum := sha256.Sum256([]byte(salt + ":" + password))
	return hex.EncodeToString(sum[:])
}

func (c *credentials) setupRequired() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.user == "" || (c.bcryptHash == "" && c.legacyHash == "")
}

// validateUsername rejects empty, overlong, and control/quote characters that
// would break the line-based panel.env format or allow injection (F24).
func validateUsername(user string) error {
	if user == "" {
		return fmt.Errorf("логин обязателен")
	}
	if len(user) > maxUsernameLen {
		return fmt.Errorf("логин слишком длинный")
	}
	for _, r := range user {
		if r < 0x20 || r == 0x7f || r == '\'' || r == '"' || r == '\\' {
			return fmt.Errorf("логин содержит недопустимый символ")
		}
	}
	return nil
}

func validatePassword(password string) error {
	if len(password) < minPasswordLen {
		return fmt.Errorf("пароль должен быть не короче %d символов", minPasswordLen)
	}
	if len(password) > maxPasswordLen {
		return fmt.Errorf("пароль слишком длинный (макс. %d)", maxPasswordLen)
	}
	return nil
}

// set replaces the stored credentials. It validates the username/password,
// hashes with bcrypt, persists atomically, and only then publishes the new
// values in memory — so a persistence failure never leaves memory and disk
// diverged (F24).
func (c *credentials) set(user, password string) error {
	if err := validateUsername(user); err != nil {
		return err
	}
	if err := validatePassword(password); err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.persistLocked(user, string(hash)); err != nil {
		return err
	}
	c.user = user
	c.bcryptHash = string(hash)
	c.legacySalt = ""
	c.legacyHash = ""
	return nil
}

// createInitial performs the first-run credential bootstrap as a single
// transactional, locked operation that succeeds exactly once, closing the
// check-then-set race on the unauthenticated setup endpoint (F03).
func (c *credentials) createInitial(user, password string) error {
	c.mu.Lock()
	alreadySet := c.user != "" && (c.bcryptHash != "" || c.legacyHash != "")
	c.mu.Unlock()
	if alreadySet {
		return fmt.Errorf("панель уже настроена")
	}
	if err := validateUsername(user); err != nil {
		return err
	}
	if err := validatePassword(password); err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.user != "" && (c.bcryptHash != "" || c.legacyHash != "") {
		return fmt.Errorf("панель уже настроена")
	}
	if err := c.persistLocked(user, string(hash)); err != nil {
		return err
	}
	c.user = user
	c.bcryptHash = string(hash)
	c.legacySalt = ""
	c.legacyHash = ""
	return nil
}

// verify checks the username and password in constant time. A successful match
// against a legacy SHA-256 hash transparently re-hashes with bcrypt.
func (c *credentials) verify(user, password string) bool {
	c.mu.RLock()
	storedUser := c.user
	bcryptHash := c.bcryptHash
	legacySalt := c.legacySalt
	legacyHash := c.legacyHash
	c.mu.RUnlock()

	if storedUser == "" {
		return false
	}
	userOK := subtle.ConstantTimeCompare([]byte(user), []byte(storedUser)) == 1

	if bcryptHash != "" {
		passOK := bcrypt.CompareHashAndPassword([]byte(bcryptHash), []byte(password)) == nil
		return userOK && passOK
	}
	if legacyHash != "" {
		passOK := subtle.ConstantTimeCompare(
			[]byte(legacyHashPassword(legacySalt, password)),
			[]byte(legacyHash),
		) == 1
		if userOK && passOK {
			// Migrate to bcrypt; ignore migration failure (auth still succeeds).
			_ = c.set(storedUser, password)
			return true
		}
		return false
	}
	return false
}

func (c *credentials) username() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.user
}

// persistLocked writes panel.env atomically. The caller must hold c.mu.
func (c *credentials) persistLocked(user, bcryptHash string) error {
	body := fmt.Sprintf(
		"ZANOZA_PANEL_USER='%s'\nZANOZA_PANEL_PASS_BCRYPT='%s'\n",
		user, bcryptHash,
	)
	if err := os.MkdirAll(dirOf(c.envPath), 0o755); err != nil {
		return err
	}
	return writeFileAtomic(c.envPath, []byte(body), 0o600)
}

// ---------------------------------------------------------------------------
// Login rate limiting (F07)
// ---------------------------------------------------------------------------

type loginLimiter struct {
	mu       sync.Mutex
	attempts map[string]*attemptRecord
	max      int           // failures before lockout
	window   time.Duration // lockout duration
	cap      int           // max tracked keys (bounded memory)
}

type attemptRecord struct {
	count     int
	lockUntil time.Time
	seen      time.Time
}

func newLoginLimiter(max int, window time.Duration) *loginLimiter {
	return &loginLimiter{
		attempts: make(map[string]*attemptRecord),
		max:      max,
		window:   window,
		cap:      4096,
	}
}

// allowed reports whether key may attempt authentication now.
func (l *loginLimiter) allowed(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	rec := l.attempts[key]
	if rec == nil {
		return true
	}
	if !rec.lockUntil.IsZero() && time.Now().Before(rec.lockUntil) {
		return false
	}
	return true
}

func (l *loginLimiter) fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.attempts) >= l.cap {
		l.evictLocked()
	}
	rec := l.attempts[key]
	if rec == nil {
		rec = &attemptRecord{}
		l.attempts[key] = rec
	}
	rec.count++
	rec.seen = time.Now()
	if rec.count >= l.max {
		rec.lockUntil = time.Now().Add(l.window)
		rec.count = 0
	}
}

func (l *loginLimiter) reset(key string) {
	l.mu.Lock()
	delete(l.attempts, key)
	l.mu.Unlock()
}

// evictLocked drops the oldest-seen entries when the table is full.
func (l *loginLimiter) evictLocked() {
	now := time.Now()
	for k, rec := range l.attempts {
		if rec.lockUntil.IsZero() && now.Sub(rec.seen) > l.window {
			delete(l.attempts, k)
		}
	}
	// If still full, drop arbitrary entries to stay bounded.
	for k := range l.attempts {
		if len(l.attempts) < l.cap {
			break
		}
		delete(l.attempts, k)
	}
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

type sessionStore struct {
	mu       sync.Mutex
	sessions map[string]time.Time
	ttl      time.Duration
	max      int
}

func newSessionStore() *sessionStore {
	return &sessionStore{sessions: map[string]time.Time{}, ttl: 12 * time.Hour, max: 10000}
}

// create mints a session token. It returns an error if secure randomness is
// unavailable — it never falls back to a predictable value (F28).
func (s *sessionStore) create() (string, error) {
	token, err := randomTokenStrict(32)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	s.sweepLocked()
	if len(s.sessions) >= s.max {
		// Hard cap: refuse rather than grow unbounded.
		s.mu.Unlock()
		return "", fmt.Errorf("too many active sessions")
	}
	s.sessions[token] = time.Now().Add(s.ttl)
	s.mu.Unlock()
	return token, nil
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

// revokeAll drops every session; used on password/username change (F07).
func (s *sessionStore) revokeAll() {
	s.mu.Lock()
	s.sessions = make(map[string]time.Time)
	s.mu.Unlock()
}

// sweepLocked removes expired sessions. Caller holds s.mu.
func (s *sessionStore) sweepLocked() {
	now := time.Now()
	for tok, exp := range s.sessions {
		if now.After(exp) {
			delete(s.sessions, tok)
		}
	}
}

// randomTokenStrict returns a hex token from crypto/rand, or an error. Security
// authenticators must fail closed rather than substitute weak entropy (F28).
func randomTokenStrict(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("secure randomness unavailable: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// randomToken is for NON-security identifiers (e.g. instance IDs) only. It still
// uses crypto/rand; callers must not use it for authenticators.
func randomToken(nBytes int) string {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func dirOf(path string) string {
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		if i == 0 {
			return "/"
		}
		return path[:i]
	}
	return "."
}
