package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image/png"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const (
	maxMFAFileBytes = 32 << 10
	mfaIssuer       = "Zanoza Panel"
	mfaPeriod       = 30
)

type mfaState struct {
	Enabled       bool   `json:"enabled"`
	Secret        string `json:"secret,omitempty"`
	PendingSecret string `json:"pending_secret,omitempty"`
	Prompted      bool   `json:"prompted"`
	UpdatedAt     string `json:"updated_at,omitempty"`
}

type mfaStatus struct {
	Enabled  bool `json:"enabled"`
	Prompted bool `json:"prompted"`
}

type mfaSetupView struct {
	Secret     string `json:"secret"`
	OtpauthURL string `json:"otpauth_url"`
	QRDataURL  string `json:"qr_data_url"`
}

type mfaStore struct {
	mu      sync.Mutex
	path    string
	state   mfaState
	loadErr error
}

func loadMFAStore(path string) *mfaStore {
	store := &mfaStore{path: path}
	raw, err := readFileLimited(path, maxMFAFileBytes)
	if err != nil {
		if !os.IsNotExist(err) {
			store.loadErr = fmt.Errorf("read %s: %w", path, err)
		}
		return store
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&store.state); err != nil {
		store.loadErr = fmt.Errorf("parse %s: %w", path, err)
		return store
	}
	var extra struct{}
	if err := dec.Decode(&extra); err != io.EOF {
		store.loadErr = fmt.Errorf("parse %s: trailing JSON data", path)
		return store
	}
	if err := store.validateLocked(); err != nil {
		store.loadErr = fmt.Errorf("parse %s: %w", path, err)
		return store
	}
	if err := tightenCredentialFileMode(path); err != nil {
		store.loadErr = err
	}
	return store
}

func (m *mfaStore) loadError() error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.loadErr
}

func (m *mfaStore) status() mfaStatus {
	if m == nil {
		return mfaStatus{Prompted: true}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return mfaStatus{Enabled: m.state.Enabled, Prompted: m.state.Prompted}
}

func (m *mfaStore) startSetup(account string) (mfaSetupView, error) {
	if m == nil {
		return mfaSetupView{}, fmt.Errorf("MFA storage unavailable")
	}
	if strings.TrimSpace(account) == "" {
		account = "admin"
	}
	view, err := generateMFASetup(account)
	if err != nil {
		return mfaSetupView{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.loadErr != nil {
		return mfaSetupView{}, m.loadErr
	}
	m.state.PendingSecret = view.Secret
	m.state.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if err := m.persistLocked(); err != nil {
		return mfaSetupView{}, err
	}
	return view, nil
}

func (m *mfaStore) confirmSetup(code, currentCode string) error {
	return m.confirmSetupWithCurrent(code, currentCode, true)
}

func (m *mfaStore) forceConfirmSetup(code string) error {
	return m.confirmSetupWithCurrent(code, "", false)
}

func (m *mfaStore) confirmSetupWithCurrent(code, currentCode string, requireCurrent bool) error {
	if m == nil {
		return fmt.Errorf("MFA storage unavailable")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.loadErr != nil {
		return m.loadErr
	}
	if m.state.PendingSecret == "" {
		return fmt.Errorf("сначала начните настройку 2FA")
	}
	if requireCurrent && m.state.Enabled && !validateTOTPCode(m.state.Secret, currentCode) {
		return fmt.Errorf("текущий код 2FA неверен")
	}
	if !validateTOTPCode(m.state.PendingSecret, code) {
		return fmt.Errorf("код 2FA неверен")
	}
	m.state.Enabled = true
	m.state.Secret = m.state.PendingSecret
	m.state.PendingSecret = ""
	m.state.Prompted = true
	m.state.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	return m.persistLocked()
}

func (m *mfaStore) skipSetup() error {
	if m == nil {
		return fmt.Errorf("MFA storage unavailable")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.loadErr != nil {
		return m.loadErr
	}
	m.state.PendingSecret = ""
	m.state.Prompted = true
	m.state.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	return m.persistLocked()
}

func (m *mfaStore) disable(code string) error {
	if m == nil {
		return fmt.Errorf("MFA storage unavailable")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.loadErr != nil {
		return m.loadErr
	}
	if m.state.Enabled && !validateTOTPCode(m.state.Secret, code) {
		return fmt.Errorf("код 2FA неверен")
	}
	m.state.Enabled = false
	m.state.Secret = ""
	m.state.PendingSecret = ""
	m.state.Prompted = true
	m.state.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	return m.persistLocked()
}

func (m *mfaStore) forceDisable() error {
	if m == nil {
		return fmt.Errorf("MFA storage unavailable")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.loadErr != nil {
		return m.loadErr
	}
	m.state.Enabled = false
	m.state.Secret = ""
	m.state.PendingSecret = ""
	m.state.Prompted = true
	m.state.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	return m.persistLocked()
}

func (m *mfaStore) verify(code string) bool {
	if m == nil {
		return true
	}
	m.mu.Lock()
	enabled := m.state.Enabled
	secret := m.state.Secret
	m.mu.Unlock()
	return enabled && validateTOTPCode(secret, code)
}

func (m *mfaStore) validateLocked() error {
	if m.state.Enabled && m.state.Secret == "" {
		return fmt.Errorf("enabled MFA has no secret")
	}
	if m.state.Secret != "" {
		if err := validateTOTPSecret(m.state.Secret); err != nil {
			return err
		}
	}
	if m.state.PendingSecret != "" {
		if err := validateTOTPSecret(m.state.PendingSecret); err != nil {
			return err
		}
	}
	return nil
}

func (m *mfaStore) persistLocked() error {
	if err := os.MkdirAll(dirOf(m.path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(m.state, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return writeFileAtomic(m.path, raw, 0o600)
}

func generateMFASetup(account string) (mfaSetupView, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      mfaIssuer,
		AccountName: account,
		Period:      mfaPeriod,
		SecretSize:  20,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return mfaSetupView{}, err
	}
	img, err := key.Image(220, 220)
	if err != nil {
		return mfaSetupView{}, err
	}
	var pngBytes bytes.Buffer
	if err := png.Encode(&pngBytes, img); err != nil {
		return mfaSetupView{}, err
	}
	return mfaSetupView{
		Secret:     key.Secret(),
		OtpauthURL: key.URL(),
		QRDataURL:  "data:image/png;base64," + base64.StdEncoding.EncodeToString(pngBytes.Bytes()),
	}, nil
}

func validateTOTPCode(secret, code string) bool {
	code = sanitizeTOTPCode(code)
	if code == "" {
		return false
	}
	ok, err := totp.ValidateCustom(code, secret, time.Now().UTC(), totp.ValidateOpts{
		Period:    mfaPeriod,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	return err == nil && ok
}

func sanitizeTOTPCode(code string) string {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != 6 {
		return ""
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			return ""
		}
	}
	return code
}

func validateTOTPSecret(secret string) error {
	if len(secret) < 16 || len(secret) > 128 {
		return fmt.Errorf("invalid TOTP secret length")
	}
	for _, r := range secret {
		if (r < 'A' || r > 'Z') && (r < '2' || r > '7') {
			return fmt.Errorf("invalid TOTP secret alphabet")
		}
	}
	return nil
}

func readMFACode(reader io.Reader) (string, error) {
	if reader == nil {
		return "", fmt.Errorf("MFA code input is unavailable")
	}
	raw, err := io.ReadAll(io.LimitReader(reader, 32))
	if err != nil {
		return "", err
	}
	code := sanitizeTOTPCode(string(raw))
	if code == "" {
		return "", fmt.Errorf("код 2FA должен состоять из 6 цифр")
	}
	return code, nil
}

type mfaTicketKind string

const (
	mfaTicketVerify mfaTicketKind = "verify"
	mfaTicketSetup  mfaTicketKind = "setup"
)

type mfaTicket struct {
	kind   mfaTicketKind
	expiry time.Time
}

type mfaTicketStore struct {
	mu      sync.Mutex
	tickets map[string]mfaTicket
	ttl     time.Duration
	max     int
}

func newMFATicketStore() *mfaTicketStore {
	return &mfaTicketStore{tickets: map[string]mfaTicket{}, ttl: 5 * time.Minute, max: 1024}
}

func (s *mfaTicketStore) create(kind mfaTicketKind) (string, error) {
	if s == nil {
		return "", fmt.Errorf("MFA ticket storage unavailable")
	}
	token, err := randomTokenStrict(32)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	if len(s.tickets) >= s.max {
		return "", fmt.Errorf("too many pending MFA challenges")
	}
	s.tickets[token] = mfaTicket{kind: kind, expiry: time.Now().Add(s.ttl)}
	return token, nil
}

func (s *mfaTicketStore) valid(token string, kind mfaTicketKind) bool {
	if s == nil || token == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ticket, ok := s.tickets[token]
	if !ok || ticket.kind != kind || time.Now().After(ticket.expiry) {
		delete(s.tickets, token)
		return false
	}
	return true
}

func (s *mfaTicketStore) consume(token string, kind mfaTicketKind) bool {
	if s == nil || token == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ticket, ok := s.tickets[token]
	delete(s.tickets, token)
	return ok && ticket.kind == kind && !time.Now().After(ticket.expiry)
}

func (s *mfaTicketStore) revokeAll() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.tickets = map[string]mfaTicket{}
	s.mu.Unlock()
}

func (s *mfaTicketStore) sweepLocked() {
	now := time.Now()
	for token, ticket := range s.tickets {
		if now.After(ticket.expiry) {
			delete(s.tickets, token)
		}
	}
}
