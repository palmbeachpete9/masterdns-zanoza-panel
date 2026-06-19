package main

import (
	"net/http"
	"strings"
)

func (s *server) mfaLoginResponse(w http.ResponseWriter) bool {
	status := s.mfa.status()
	switch {
	case status.Enabled:
		ticket, err := s.mfaTickets.create(mfaTicketVerify)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "MFA challenge error")
			return false
		}
		writeJSON(w, map[string]any{"ok": true, "mfa_required": true, "ticket": ticket})
		return false
	case !status.Prompted:
		ticket, err := s.mfaTickets.create(mfaTicketSetup)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "MFA setup error")
			return false
		}
		writeJSON(w, map[string]any{"ok": true, "mfa_setup_required": true, "ticket": ticket})
		return false
	default:
		return true
	}
}

func (s *server) issueSession(w http.ResponseWriter) bool {
	token, err := s.sessions.create()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "session error")
		return false
	}
	s.setSessionCookie(w, token)
	writeJSON(w, map[string]any{"ok": true})
	return true
}

func (s *server) rotateSession(w http.ResponseWriter) bool {
	s.sessions.revokeAll()
	s.mfaTickets.revokeAll()
	return s.issueSession(w)
}

func (s *server) handleAuthMFAVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.sameOriginOK(r) {
		writeErr(w, http.StatusForbidden, "cross-origin request rejected")
		return
	}
	var body struct {
		Ticket string `json:"ticket"`
		Code   string `json:"code"`
	}
	if err := readJSON(w, r, &body); err != nil {
		writeBadBody(w, err)
		return
	}
	limitKey := "mfa:" + s.clientIP(r)
	if !s.limiter.allowed(limitKey) {
		writeErr(w, http.StatusTooManyRequests, "слишком много попыток, попробуйте позже")
		return
	}
	defer s.limiter.release(limitKey)
	if !s.mfaTickets.valid(body.Ticket, mfaTicketVerify) || !s.mfa.verify(body.Code) {
		s.limiter.fail(limitKey)
		writeErr(w, http.StatusUnauthorized, "код 2FA неверен")
		return
	}
	if !s.mfaTickets.consume(body.Ticket, mfaTicketVerify) {
		writeErr(w, http.StatusUnauthorized, "сеанс 2FA истёк")
		return
	}
	s.limiter.reset(limitKey)
	s.issueSession(w)
}

func (s *server) handleAuthMFASetupStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.sameOriginOK(r) {
		writeErr(w, http.StatusForbidden, "cross-origin request rejected")
		return
	}
	var body struct {
		Ticket string `json:"ticket"`
	}
	if err := readJSON(w, r, &body); err != nil {
		writeBadBody(w, err)
		return
	}
	authed := s.authenticated(r)
	if !authed && !s.mfaTickets.valid(body.Ticket, mfaTicketSetup) {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	view, err := s.mfa.startSetup(s.creds.username())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, view)
}

func (s *server) handleAuthMFASetupConfirm(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.sameOriginOK(r) {
		writeErr(w, http.StatusForbidden, "cross-origin request rejected")
		return
	}
	var body struct {
		Ticket      string `json:"ticket"`
		Code        string `json:"code"`
		CurrentCode string `json:"current_code"`
	}
	if err := readJSON(w, r, &body); err != nil {
		writeBadBody(w, err)
		return
	}

	authed := s.authenticated(r)
	if !authed && !s.mfaTickets.valid(body.Ticket, mfaTicketSetup) {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	limitKey := "mfa:" + s.clientIP(r)
	if !s.limiter.allowed(limitKey) {
		writeErr(w, http.StatusTooManyRequests, "слишком много попыток, попробуйте позже")
		return
	}
	defer s.limiter.release(limitKey)

	s.authMu.Lock()
	defer s.authMu.Unlock()
	if err := s.mfa.confirmSetup(body.Code, body.CurrentCode); err != nil {
		s.limiter.fail(limitKey)
		writeErr(w, http.StatusForbidden, err.Error())
		return
	}
	if !authed && !s.mfaTickets.consume(body.Ticket, mfaTicketSetup) {
		writeErr(w, http.StatusUnauthorized, "сеанс настройки 2FA истёк")
		return
	}
	s.limiter.reset(limitKey)
	s.rotateSession(w)
}

func (s *server) handleAuthMFASkip(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.sameOriginOK(r) {
		writeErr(w, http.StatusForbidden, "cross-origin request rejected")
		return
	}
	var body struct {
		Ticket string `json:"ticket"`
	}
	if err := readJSON(w, r, &body); err != nil {
		writeBadBody(w, err)
		return
	}
	if !s.mfaTickets.consume(body.Ticket, mfaTicketSetup) {
		writeErr(w, http.StatusUnauthorized, "сеанс настройки 2FA истёк")
		return
	}
	if s.mfa.status().Enabled {
		writeErr(w, http.StatusForbidden, "2FA уже включена")
		return
	}
	s.authMu.Lock()
	defer s.authMu.Unlock()
	if err := s.mfa.skipSetup(); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.issueSession(w)
}

func (s *server) handleAuthMFADisable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := readJSON(w, r, &body); err != nil {
		writeBadBody(w, err)
		return
	}
	limitKey := "mfa:" + s.clientIP(r)
	if !s.limiter.allowed(limitKey) {
		writeErr(w, http.StatusTooManyRequests, "слишком много попыток, попробуйте позже")
		return
	}
	defer s.limiter.release(limitKey)

	s.authMu.Lock()
	defer s.authMu.Unlock()
	if err := s.mfa.disable(strings.TrimSpace(body.Code)); err != nil {
		s.limiter.fail(limitKey)
		writeErr(w, http.StatusForbidden, err.Error())
		return
	}
	s.limiter.reset(limitKey)
	s.rotateSession(w)
}
