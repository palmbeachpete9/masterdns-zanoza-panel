package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func TestLoginRequiresMFASetupBeforeFirstSession(t *testing.T) {
	s := newTestServer(t)
	if err := s.creds.set("admin", "longenough1"); err != nil {
		t.Fatal(err)
	}

	login := postJSON("/admin/api/auth/login", `{"user":"admin","password":"longenough1"}`)
	w := httptest.NewRecorder()
	s.handleAuthLogin(w, login)
	if w.Code != http.StatusOK {
		t.Fatalf("login returned %d", w.Code)
	}
	body := decodeJSONBody(t, w)
	ticket := stringField(t, body, "ticket")
	if body["mfa_setup_required"] != true {
		t.Fatalf("login body = %#v, want mfa_setup_required", body)
	}
	if len(w.Result().Cookies()) != 0 {
		t.Fatal("password-only first login issued a session before MFA setup/skip")
	}

	start := postJSON("/admin/api/auth/mfa/setup/start", `{"ticket":`+quoteJSON(ticket)+`}`)
	w = httptest.NewRecorder()
	s.handleAuthMFASetupStart(w, start)
	if w.Code != http.StatusOK {
		t.Fatalf("setup start returned %d: %s", w.Code, w.Body.String())
	}
	setup := decodeJSONBody(t, w)
	secret := stringField(t, setup, "secret")
	if stringField(t, setup, "qr_data_url") == "" {
		t.Fatal("setup response did not include a QR data URL")
	}
	code := currentTOTP(t, secret)

	confirm := postJSON("/admin/api/auth/mfa/setup/confirm", `{"ticket":`+quoteJSON(ticket)+`,"code":`+quoteJSON(code)+`}`)
	w = httptest.NewRecorder()
	s.handleAuthMFASetupConfirm(w, confirm)
	if w.Code != http.StatusOK {
		t.Fatalf("setup confirm returned %d: %s", w.Code, w.Body.String())
	}
	if len(w.Result().Cookies()) == 0 {
		t.Fatal("confirmed MFA setup did not issue a session")
	}
	if !s.mfa.status().Enabled {
		t.Fatal("MFA was not enabled after setup confirmation")
	}
}

func TestLoginRequiresTOTPWhenMFAEnabled(t *testing.T) {
	s := newTestServer(t)
	if err := s.creds.set("admin", "longenough1"); err != nil {
		t.Fatal(err)
	}
	view, err := s.mfa.startSetup("admin")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.mfa.forceConfirmSetup(currentTOTP(t, view.Secret)); err != nil {
		t.Fatal(err)
	}

	login := postJSON("/admin/api/auth/login", `{"user":"admin","password":"longenough1"}`)
	w := httptest.NewRecorder()
	s.handleAuthLogin(w, login)
	if w.Code != http.StatusOK {
		t.Fatalf("login returned %d", w.Code)
	}
	body := decodeJSONBody(t, w)
	ticket := stringField(t, body, "ticket")
	if body["mfa_required"] != true {
		t.Fatalf("login body = %#v, want mfa_required", body)
	}
	if len(w.Result().Cookies()) != 0 {
		t.Fatal("password-only login issued a session while MFA is enabled")
	}

	verify := postJSON("/admin/api/auth/mfa/verify", `{"ticket":`+quoteJSON(ticket)+`,"code":`+quoteJSON(currentTOTP(t, view.Secret))+`}`)
	w = httptest.NewRecorder()
	s.handleAuthMFAVerify(w, verify)
	if w.Code != http.StatusOK {
		t.Fatalf("MFA verify returned %d: %s", w.Code, w.Body.String())
	}
	if len(w.Result().Cookies()) == 0 {
		t.Fatal("MFA verify did not issue a session")
	}
}

func TestSkippingFirstMFASetupAllowsFuturePasswordLogin(t *testing.T) {
	s := newTestServer(t)
	if err := s.creds.set("admin", "longenough1"); err != nil {
		t.Fatal(err)
	}

	login := postJSON("/admin/api/auth/login", `{"user":"admin","password":"longenough1"}`)
	w := httptest.NewRecorder()
	s.handleAuthLogin(w, login)
	ticket := stringField(t, decodeJSONBody(t, w), "ticket")

	skip := postJSON("/admin/api/auth/mfa/skip", `{"ticket":`+quoteJSON(ticket)+`}`)
	w = httptest.NewRecorder()
	s.handleAuthMFASkip(w, skip)
	if w.Code != http.StatusOK {
		t.Fatalf("MFA skip returned %d: %s", w.Code, w.Body.String())
	}
	if !s.mfa.status().Prompted {
		t.Fatal("MFA skip did not mark the first prompt complete")
	}

	login = postJSON("/admin/api/auth/login", `{"user":"admin","password":"longenough1"}`)
	w = httptest.NewRecorder()
	s.handleAuthLogin(w, login)
	if w.Code != http.StatusOK {
		t.Fatalf("second login returned %d: %s", w.Code, w.Body.String())
	}
	body := decodeJSONBody(t, w)
	if body["mfa_setup_required"] == true || body["mfa_required"] == true {
		t.Fatalf("second login unexpectedly required MFA: %#v", body)
	}
	if len(w.Result().Cookies()) == 0 {
		t.Fatal("second password login did not issue a session")
	}
}

func postJSON(path, body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "http://panel.local"+path, strings.NewReader(body))
	req.Host = "panel.local"
	req.RemoteAddr = "192.0.2.1:12345"
	req.Header.Set("Origin", "http://panel.local")
	req.Header.Set("Content-Type", "application/json")
	return req
}

func decodeJSONBody(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode JSON body %q: %v", w.Body.String(), err)
	}
	return body
}

func stringField(t *testing.T, body map[string]any, key string) string {
	t.Helper()
	value, _ := body[key].(string)
	if value == "" {
		t.Fatalf("missing string field %q in %#v", key, body)
	}
	return value
}

func currentTOTP(t *testing.T, secret string) string {
	t.Helper()
	code, err := totp.GenerateCode(secret, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func quoteJSON(value string) string {
	raw, _ := json.Marshal(value)
	return string(raw)
}
