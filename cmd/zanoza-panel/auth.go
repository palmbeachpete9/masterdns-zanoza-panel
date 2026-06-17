package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
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

	// loadErr is set when panel.env exists but could not be read or parsed into
	// usable credentials. It must make the panel fail closed — never be treated
	// as a fresh first-run that reopens unauthenticated setup (V4-02).
	loadErr error
}

const (
	minPasswordLen         = 8
	maxPasswordLen         = 72 // bcrypt input ceiling
	maxUsernameLen         = 64
	bcryptCost             = 12
	maxAcceptedBcryptCost  = 16
	maxCredentialFileBytes = 128 << 10
)

func loadCredentials(envPath string) *credentials {
	c := &credentials{envPath: envPath}
	raw, err := readFileLimited(envPath, maxCredentialFileBytes)
	if err != nil {
		// A genuinely absent file is first-run. ANY other error (permission
		// denied, I/O) must fail closed, not be mistaken for first-run (V4-02).
		if !os.IsNotExist(err) {
			c.loadErr = fmt.Errorf("read %s: %w", envPath, err)
		}
		return c
	}
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	seen := make(map[string]struct{}, 4)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			c.loadErr = fmt.Errorf("parse %s: malformed credential line", envPath)
			return c
		}
		key = strings.TrimSpace(key)
		val, err = parseCredentialValue(val)
		if err != nil {
			c.loadErr = fmt.Errorf("parse %s: invalid %s value: %w", envPath, key, err)
			return c
		}
		switch key {
		case "ZANOZA_PANEL_USER":
			if _, duplicate := seen[key]; duplicate {
				c.loadErr = fmt.Errorf("parse %s: duplicate %s", envPath, key)
				return c
			}
			seen[key] = struct{}{}
			c.user = val
		case "ZANOZA_PANEL_PASS_BCRYPT":
			if _, duplicate := seen[key]; duplicate {
				c.loadErr = fmt.Errorf("parse %s: duplicate %s", envPath, key)
				return c
			}
			seen[key] = struct{}{}
			c.bcryptHash = val
		case "ZANOZA_PANEL_SALT":
			if _, duplicate := seen[key]; duplicate {
				c.loadErr = fmt.Errorf("parse %s: duplicate %s", envPath, key)
				return c
			}
			seen[key] = struct{}{}
			c.legacySalt = val
		case "ZANOZA_PANEL_PASS_HASH":
			if _, duplicate := seen[key]; duplicate {
				c.loadErr = fmt.Errorf("parse %s: duplicate %s", envPath, key)
				return c
			}
			seen[key] = struct{}{}
			c.legacyHash = val
		}
	}
	if err := scanner.Err(); err != nil {
		c.loadErr = fmt.Errorf("parse %s: %w", envPath, err)
		return c
	}
	// A file that exists but does not parse into a usable credential is treated
	// as malformed and fails closed (e.g. an interrupted write) (V4-02).
	if c.user == "" || (c.bcryptHash == "" && c.legacyHash == "") {
		c.loadErr = fmt.Errorf("%s exists but holds no usable credentials", envPath)
		return c
	}
	if err := validateUsername(c.user); err != nil {
		c.loadErr = fmt.Errorf("parse %s: invalid username: %w", envPath, err)
		return c
	}
	if c.bcryptHash != "" {
		cost, err := bcrypt.Cost([]byte(c.bcryptHash))
		if err != nil {
			c.loadErr = fmt.Errorf("parse %s: invalid bcrypt hash: %w", envPath, err)
		} else if cost > maxAcceptedBcryptCost {
			c.loadErr = fmt.Errorf("parse %s: bcrypt cost %d exceeds limit %d", envPath, cost, maxAcceptedBcryptCost)
		} else if err := tightenCredentialFileMode(envPath); err != nil {
			c.loadErr = err
		}
		return c
	}
	decodedHash, err := hex.DecodeString(c.legacyHash)
	if c.legacySalt == "" || err != nil || len(decodedHash) != sha256.Size {
		c.loadErr = fmt.Errorf("parse %s: invalid legacy credentials", envPath)
	} else if err := tightenCredentialFileMode(envPath); err != nil {
		c.loadErr = err
	}
	return c
}

func tightenCredentialFileMode(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect credential file %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("credential file %s must be a regular non-symlink file", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open credential file %s: %w", path, err)
	}
	defer func() { _ = file.Close() }()
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return fmt.Errorf("credential file %s changed while opening", path)
	}
	if err := file.Chmod(0o600); err != nil {
		return fmt.Errorf("secure credential file %s: %w", path, err)
	}
	currentInfo, err := os.Lstat(path)
	if err != nil || currentInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(openedInfo, currentInfo) {
		return fmt.Errorf("credential file %s changed while securing", path)
	}
	return nil
}

func parseCredentialValue(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", nil
	}
	first := value[0]
	last := value[len(value)-1]
	if first == '\'' || first == '"' {
		if len(value) < 2 || last != first {
			return "", fmt.Errorf("unmatched quote")
		}
		return value[1 : len(value)-1], nil
	}
	if last == '\'' || last == '"' {
		return "", fmt.Errorf("unmatched quote")
	}
	return value, nil
}

// loadError reports a credential read/parse failure, if any.
func (c *credentials) loadError() error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.loadErr
}

func legacyHashPassword(salt, password string) string {
	sum := sha256.Sum256([]byte(salt + ":" + password))
	return hex.EncodeToString(sum[:])
}

func (c *credentials) setupRequired() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	// Unreadable/malformed credentials are NOT first-run: fail closed so the
	// unauthenticated setup endpoint stays disabled (V4-02).
	if c.loadErr != nil {
		return false
	}
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

func readCredentialPassword(reader io.Reader) (string, error) {
	if reader == nil {
		return "", fmt.Errorf("password input is unavailable")
	}
	raw, err := io.ReadAll(io.LimitReader(reader, maxPasswordLen+1))
	if err != nil {
		return "", err
	}
	password := string(raw)
	if err := validatePassword(password); err != nil {
		return "", err
	}
	return password, nil
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

// changePassword verifies and replaces the current password as one serialized
// credential transaction. This prevents two concurrent requests that both
// verified the old password from racing to publish different replacements.
// The bool reports whether the supplied current password matched.
func (c *credentials) changePassword(current, password string) (bool, error) {
	if err := validatePassword(password); err != nil {
		return false, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	matches := false
	switch {
	case c.user == "":
		return false, nil
	case c.bcryptHash != "":
		matches = bcrypt.CompareHashAndPassword([]byte(c.bcryptHash), []byte(current)) == nil
	case c.legacyHash != "":
		matches = subtle.ConstantTimeCompare(
			[]byte(legacyHashPassword(c.legacySalt, current)),
			[]byte(c.legacyHash),
		) == 1
	}
	if !matches {
		return false, nil
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return true, err
	}
	if err := c.persistLocked(c.user, string(hash)); err != nil {
		return true, err
	}
	c.bcryptHash = string(hash)
	c.legacySalt = ""
	c.legacyHash = ""
	return true, nil
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
	if c.loadErr != nil {
		return c.loadErr
	}
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
	if err := os.MkdirAll(dirOf(c.envPath), 0o700); err != nil {
		return err
	}
	return writeFileAtomic(c.envPath, []byte(body), 0o600)
}

// ---------------------------------------------------------------------------
// Login rate limiting (F07)
// ---------------------------------------------------------------------------

type loginLimiter struct {
	mu          sync.Mutex
	attempts    map[string]*attemptRecord
	max         int           // failures before lockout
	window      time.Duration // lockout duration
	cap         int           // max tracked keys (bounded memory)
	inflight    int           // bcrypt checks currently running
	maxInflight int           // global bcrypt concurrency ceiling
}

type attemptRecord struct {
	count     int
	lockUntil time.Time
	seen      time.Time
	inflight  bool
}

func newLoginLimiter(max int, window time.Duration) *loginLimiter {
	return &loginLimiter{
		attempts:    make(map[string]*attemptRecord),
		max:         max,
		window:      window,
		cap:         4096,
		maxInflight: 8,
	}
}

// allowed reserves one bounded bcrypt verification slot for key. Only one
// verification per source and maxInflight verifications globally may run at
// once, so a concurrent login burst cannot bypass failure accounting or exhaust
// the server with unbounded bcrypt work.
func (l *loginLimiter) allowed(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	rec := l.attempts[key]
	if rec == nil {
		if l.inflight >= l.maxInflight {
			return false
		}
		if len(l.attempts) >= l.cap {
			l.evictLocked()
			// Fail closed when every slot is an active lockout. Evicting a
			// locked record would let an attacker bypass throttling by spraying
			// distinct source addresses until the victim record disappears.
			if len(l.attempts) >= l.cap {
				return false
			}
		}
		rec = &attemptRecord{}
		l.attempts[key] = rec
	}
	if !rec.lockUntil.IsZero() && time.Now().Before(rec.lockUntil) {
		return false
	}
	if !rec.lockUntil.IsZero() {
		rec.lockUntil = time.Time{}
		rec.count = 0
	}
	if rec.inflight || l.inflight >= l.maxInflight {
		return false
	}
	rec.inflight = true
	rec.seen = time.Now()
	l.inflight++
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
		if len(l.attempts) >= l.cap {
			return
		}
		rec = &attemptRecord{}
		l.attempts[key] = rec
	}
	if rec.inflight {
		rec.inflight = false
		if l.inflight > 0 {
			l.inflight--
		}
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
	if rec := l.attempts[key]; rec != nil && rec.inflight && l.inflight > 0 {
		l.inflight--
	}
	delete(l.attempts, key)
	l.mu.Unlock()
}

func (l *loginLimiter) release(key string) {
	l.mu.Lock()
	if rec := l.attempts[key]; rec != nil && rec.inflight {
		rec.inflight = false
		rec.seen = time.Now()
		if l.inflight > 0 {
			l.inflight--
		}
	}
	l.mu.Unlock()
}

// evictLocked drops expired/stale unlocked entries. Active lockouts are never
// evicted, because doing so would reopen a currently-throttled credential
// guessing source.
func (l *loginLimiter) evictLocked() {
	now := time.Now()
	for k, rec := range l.attempts {
		if rec.inflight {
			continue
		}
		if (!rec.lockUntil.IsZero() && !now.Before(rec.lockUntil)) ||
			(rec.lockUntil.IsZero() && now.Sub(rec.seen) > l.window) {
			delete(l.attempts, k)
		}
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
