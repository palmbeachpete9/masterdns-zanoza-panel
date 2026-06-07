// Command zanoza-panel is a web manager for MasterDnsVPN instances with
// Zanoza (iOS) support. It supervises a single forked MasterDnsVPN server
// (per-domain keyring) and lets an admin mint domain+key instances and
// export them as zanoza:// links.
package main

import (
	"crypto/tls"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

//go:embed web/dist
var embeddedWeb embed.FS

type server struct {
	cfg      *Config
	creds    *credentials
	sessions *sessionStore
	limiter  *loginLimiter
	manager  *serverManager
	webFS    fs.FS
	useTLS   bool
	mu       sync.Mutex
}

func main() {
	configPath := flag.String("config", envDefault(EnvConfig, "/etc/zanoza-panel/config.json"), "path to panel config JSON")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	applyEnvOverrides(cfg)

	configDir := filepath.Dir(*configPath)
	creds := loadCredentials(filepath.Join(configDir, "panel.env"))
	maybeAutoSetup(creds)
	manager := newServerManager(envDefault(EnvRuntimeDir, filepath.Join(configDir, "masterdns")))

	webRoot, err := fs.Sub(embeddedWeb, "web/dist")
	if err != nil {
		log.Fatalf("embed web: %v", err)
	}

	// TLS mode is explicit and fail-closed (F05): if certificate paths are
	// configured, the key pair MUST load before we listen. We never silently
	// downgrade to plaintext because a file is missing/unreadable.
	tlsConfigured := cfg.TLSCert != "" || cfg.TLSKey != ""
	useTLS := false
	if tlsConfigured {
		if cfg.TLSCert == "" || cfg.TLSKey == "" {
			log.Fatalf("TLS misconfigured: both tls_cert and tls_key are required")
		}
		if _, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey); err != nil {
			log.Fatalf("TLS enabled but key pair failed to load: %v", err)
		}
		useTLS = true
	}
	// Refuse to serve plaintext on a public interface unless explicitly
	// overridden, so credentials can't accidentally travel in the clear (F05/F03).
	if !useTLS && !isLoopbackAddr(cfg.PanelAddr) && os.Getenv("ZANOZA_ALLOW_INSECURE") != "1" {
		log.Fatalf("refusing to serve plaintext HTTP on public address %q; configure TLS or set ZANOZA_ALLOW_INSECURE=1", cfg.PanelAddr)
	}

	srv := &server{
		cfg:      cfg,
		creds:    creds,
		sessions: newSessionStore(),
		limiter:  newLoginLimiter(8, 5*time.Minute),
		manager:  manager,
		webFS:    webRoot,
		useTLS:   useTLS,
	}

	// Bring the MasterDnsVPN server up if instances already exist.
	if len(cfg.snapshot()) > 0 {
		if err := manager.apply(cfg.snapshot()); err != nil {
			log.Printf("masterdns start: %v", err)
		}
	}

	// SIGHUP re-reads config + re-applies (used by systemctl reload).
	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGHUP)
		for range ch {
			if reloaded, err := loadConfig(*configPath); err == nil {
				applyEnvOverrides(reloaded)
				srv.mu.Lock()
				srv.cfg = reloaded
				srv.mu.Unlock()
				_ = manager.apply(reloaded.snapshot())
				log.Printf("reloaded config")
			}
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.route)

	addr := fmt.Sprintf("%s:%d", cfg.PanelAddr, cfg.PanelPort)
	httpServer := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}

	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	log.Printf("zanoza-panel listening on %s://%s%s/", scheme, addr, cfg.PanelPath)

	if useTLS {
		err = httpServer.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
	} else {
		err = httpServer.ListenAndServe()
	}
	if err != nil {
		log.Fatalf("serve: %v", err)
	}
}

func isLoopbackAddr(addr string) bool {
	switch addr {
	case "", "127.0.0.1", "::1", "localhost":
		return true
	}
	if ip := net.ParseIP(addr); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// route dispatches by the configured panel path; everything outside it is a
// decoy 404 so the admin surface stays hidden.
func (s *server) route(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	path := s.cfg.PanelPath
	s.mu.Unlock()

	if r.URL.Path == "/-/reload" && r.Method == http.MethodPost {
		s.requireAuth(w, r, s.handleReload)
		return
	}

	if r.URL.Path == path {
		http.Redirect(w, r, path+"/", http.StatusFound)
		return
	}
	if !strings.HasPrefix(r.URL.Path, path+"/") {
		http.NotFound(w, r)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, path+"/")

	switch {
	case rest == "" || rest == "index.html":
		s.serveIndex(w, r)
	case strings.HasPrefix(rest, "assets/"):
		s.serveAsset(w, r, rest)
	case strings.HasPrefix(rest, "api/"):
		s.api(w, r, strings.TrimPrefix(rest, "api/"))
	default:
		// SPA fallback.
		s.serveIndex(w, r)
	}
}

func (s *server) serveIndex(w http.ResponseWriter, _ *http.Request) {
	raw, err := fs.ReadFile(s.webFS, "index.html")
	if err != nil {
		http.Error(w, "index missing", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(raw)
}

func (s *server) serveAsset(w http.ResponseWriter, r *http.Request, rest string) {
	raw, err := fs.ReadFile(s.webFS, rest)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	switch {
	case strings.HasSuffix(rest, ".js"):
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	case strings.HasSuffix(rest, ".css"):
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	}
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write(raw)
}

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------

func (s *server) api(w http.ResponseWriter, r *http.Request, rest string) {
	switch rest {
	case "auth/status":
		s.handleAuthStatus(w, r)
	case "auth/setup":
		s.handleAuthSetup(w, r)
	case "auth/login":
		s.handleAuthLogin(w, r)
	case "auth/logout":
		s.requireAuth(w, r, s.handleAuthLogout)
	case "auth/password":
		s.requireAuth(w, r, s.handleAuthPassword)
	case "state":
		s.requireAuth(w, r, s.handleState)
	case "metrics":
		s.requireAuth(w, r, s.handleMetrics)
	case "settings":
		s.requireAuth(w, r, s.handleSettings)
	case "instances":
		s.requireAuth(w, r, s.handleInstancesCollection)
	case "server/restart":
		s.requireAuth(w, r, s.handleServerRestart)
	default:
		if id, ok := strings.CutPrefix(rest, "instances/"); ok {
			s.requireAuth(w, r, func(w http.ResponseWriter, r *http.Request) {
				s.handleInstanceItem(w, r, id)
			})
			return
		}
		http.NotFound(w, r)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(msg))
}

// maxJSONBody caps unauthenticated/authenticated JSON request bodies so a slow
// or oversized body cannot exhaust memory (F08).
const maxJSONBody = 1 << 16 // 64 KiB

// errBodyTooLarge distinguishes a size-cap hit (413) from a parse error (400).
type errBodyTooLarge struct{ error }

// readJSON decodes a single JSON object from the request body with a hard size
// cap and rejects trailing data after the first value (F08). It must be given
// the ResponseWriter so http.MaxBytesReader can abort an oversized stream.
func readJSON(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBody)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return errBodyTooLarge{err}
		}
		return err
	}
	if dec.More() {
		return fmt.Errorf("unexpected trailing JSON")
	}
	return nil
}

// writeBadBody turns a readJSON error into the right status code.
func writeBadBody(w http.ResponseWriter, err error) {
	if _, ok := err.(errBodyTooLarge); ok {
		writeErr(w, http.StatusRequestEntityTooLarge, "request body too large")
		return
	}
	writeErr(w, http.StatusBadRequest, "bad request")
}

// ---------------------------------------------------------------------------
// Auth handlers
// ---------------------------------------------------------------------------

const sessionCookie = "zanoza_session"

func (s *server) authenticated(r *http.Request) bool {
	// Cookie sessions only. HTTP Basic was removed because it bypassed the
	// login endpoint's rate limiting, offering an un-throttled credential
	// guessing oracle (F07).
	if c, err := r.Cookie(sessionCookie); err == nil && s.sessions.valid(c.Value) {
		return true
	}
	return false
}

// clientIP extracts the remote host for rate-limit keying.
func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func (s *server) requireAuth(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	if !s.authenticated(r) {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	next(w, r)
}

func (s *server) setSessionCookie(w http.ResponseWriter, token string) {
	s.mu.Lock()
	path := s.cfg.PanelPath
	s.mu.Unlock()
	maxAge := 12 * 3600
	if token == "" {
		maxAge = -1 // expire immediately on logout
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     path,
		HttpOnly: true,
		Secure:   s.useTLS,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	})
}

func (s *server) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"authenticated":  s.authenticated(r),
		"setup_required": s.creds.setupRequired(),
	})
}

func (s *server) handleAuthSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.creds.setupRequired() {
		writeErr(w, http.StatusForbidden, "уже настроено")
		return
	}
	var body struct{ User, Password string }
	if err := readJSON(w, r, &body); err != nil {
		writeBadBody(w, err)
		return
	}
	// createInitial is the single transactional bootstrap: concurrent setup
	// requests resolve to exactly one owner (F03).
	if err := s.creds.createInitial(strings.TrimSpace(body.User), body.Password); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	token, err := s.sessions.create()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "session error")
		return
	}
	s.setSessionCookie(w, token)
	writeJSON(w, map[string]any{"ok": true})
}

func (s *server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	limitKey := clientIP(r)
	if !s.limiter.allowed(limitKey) {
		writeErr(w, http.StatusTooManyRequests, "слишком много попыток, попробуйте позже")
		return
	}
	var body struct{ User, Password string }
	if err := readJSON(w, r, &body); err != nil {
		writeBadBody(w, err)
		return
	}
	if !s.creds.verify(strings.TrimSpace(body.User), body.Password) {
		s.limiter.fail(limitKey)
		writeErr(w, http.StatusUnauthorized, "неверный логин или пароль")
		return
	}
	s.limiter.reset(limitKey)
	token, err := s.sessions.create()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "session error")
		return
	}
	s.setSessionCookie(w, token)
	writeJSON(w, map[string]any{"ok": true})
}

func (s *server) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.sessions.revoke(c.Value)
	}
	s.setSessionCookie(w, "")
	writeJSON(w, map[string]any{"ok": true})
}

func (s *server) handleAuthPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var body struct{ Current, Password string }
	if err := readJSON(w, r, &body); err != nil {
		writeBadBody(w, err)
		return
	}
	if !s.creds.verify(s.creds.username(), body.Current) {
		writeErr(w, http.StatusForbidden, "текущий пароль неверен")
		return
	}
	if err := s.creds.set(s.creds.username(), body.Password); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// A password change invalidates every existing session (F07).
	s.sessions.revokeAll()
	s.setSessionCookie(w, "")
	writeJSON(w, map[string]any{"ok": true})
}

// ---------------------------------------------------------------------------
// State / metrics / settings
// ---------------------------------------------------------------------------

type instanceView struct {
	Instance
	ZanozaLink string `json:"zanoza_link"`
}

func (s *server) handleState(w http.ResponseWriter, _ *http.Request) {
	cfg := s.config()
	meta := cfg.Meta() // locked snapshot; never read mutable fields directly (F12)

	instances := cfg.snapshot()
	views := make([]instanceView, 0, len(instances))
	domains := map[string]struct{}{}
	for _, ins := range instances {
		domains[ins.Domain] = struct{}{}
		views = append(views, instanceView{Instance: ins, ZanozaLink: zanozaLink(ins)})
	}

	writeJSON(w, map[string]any{
		"name":           meta.Name,
		"panel_path":     meta.PanelPath,
		"domain_count":   len(domains),
		"instance_count": len(instances),
		"server":         s.manager.state(),
		"instances":      views,
	})
}

// config returns the currently-published *Config under the server lock, so a
// SIGHUP reload swapping s.cfg never races with a handler reading it (F12).
func (s *server) config() *Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg
}

func (s *server) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	writeJSON(w, map[string]any{
		"go":     map[string]any{"version": runtime.Version(), "goroutines": runtime.NumGoroutine()},
		"memory": map[string]any{"heap_alloc_bytes": mem.HeapAlloc},
		"panel":  map[string]any{"pid": os.Getpid()},
		"server": s.manager.state(),
	})
}

func (s *server) handleSettings(w http.ResponseWriter, r *http.Request) {
	cfg := s.config()

	switch r.Method {
	case http.MethodGet:
		meta := cfg.Meta()
		writeJSON(w, map[string]any{
			"name":       meta.Name,
			"panel_path": meta.PanelPath,
			"admin_user": s.creds.username(),
		})
	case http.MethodPut:
		var body struct{ Name string }
		if err := readJSON(w, r, &body); err != nil {
			writeBadBody(w, err)
			return
		}
		cfg.mu.Lock()
		if strings.TrimSpace(body.Name) != "" {
			cfg.Name = strings.TrimSpace(body.Name)
		}
		cfg.mu.Unlock()
		if err := cfg.save(); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, map[string]any{"ok": true})
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// ---------------------------------------------------------------------------
// Instances
// ---------------------------------------------------------------------------

func isAEADMethod(method int) bool { return method >= 2 }

func (s *server) handleInstancesCollection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var in Instance
	if err := readJSON(w, r, &in); err != nil {
		writeBadBody(w, err)
		return
	}
	in.ID = newInstanceID()
	in.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	if d, err := canonicalDomain(in.Domain); err == nil {
		in.Domain = d // store canonical form (F06)
	}
	if err := s.mutateInstances(func(list []Instance) ([]Instance, error) {
		if err := validateInstance(list, in, ""); err != nil {
			return nil, err
		}
		return append(list, in), nil
	}); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, instanceView{Instance: in, ZanozaLink: zanozaLink(in)})
}

func (s *server) handleInstanceItem(w http.ResponseWriter, r *http.Request, id string) {
	switch r.Method {
	case http.MethodPut:
		var in Instance
		if err := readJSON(w, r, &in); err != nil {
			writeBadBody(w, err)
			return
		}
		if err := s.mutateInstances(func(list []Instance) ([]Instance, error) {
			idx := indexOfInstance(list, id)
			if idx < 0 {
				return nil, fmt.Errorf("инстанс не найден")
			}
			updated := list[idx]
			updated.Label = in.Label
			updated.Domain = in.Domain
			updated.Key = in.Key
			updated.Method = in.Method
			if d, err := canonicalDomain(updated.Domain); err == nil {
				updated.Domain = d // store canonical form (F06)
			}
			if err := validateInstance(list, updated, id); err != nil {
				return nil, err
			}
			list[idx] = updated
			return list, nil
		}); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, map[string]any{"ok": true})
	case http.MethodDelete:
		if err := s.mutateInstances(func(list []Instance) ([]Instance, error) {
			idx := indexOfInstance(list, id)
			if idx < 0 {
				return nil, fmt.Errorf("инстанс не найден")
			}
			return append(list[:idx], list[idx+1:]...), nil
		}); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, map[string]any{"ok": true})
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *server) handleServerRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if err := s.manager.restart(s.config().snapshot()); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (s *server) handleReload(w http.ResponseWriter, _ *http.Request) {
	if err := s.manager.apply(s.config().snapshot()); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

// mutateInstances applies fn to a copy of the instance list, persists, and
// re-applies the keyring to the running server.
func (s *server) mutateInstances(fn func([]Instance) ([]Instance, error)) error {
	s.mu.Lock()
	cfg := s.cfg
	s.mu.Unlock()

	cfg.mu.Lock()
	working := make([]Instance, len(cfg.Instances))
	copy(working, cfg.Instances)
	next, err := fn(working)
	if err != nil {
		cfg.mu.Unlock()
		return err
	}
	cfg.Instances = next
	cfg.mu.Unlock()

	if err := cfg.save(); err != nil {
		return err
	}
	// The config is the source of truth and is now saved. A failure to
	// (re)start/reload the MasterDnsVPN server (e.g. binary missing on a
	// dev box) must NOT roll back the CRUD operation — it surfaces
	// separately via state.server.exit_error.
	if err := s.manager.apply(cfg.snapshot()); err != nil {
		log.Printf("masterdns apply: %v", err)
	}
	return nil
}

func indexOfInstance(list []Instance, id string) int {
	for i, ins := range list {
		if ins.ID == id {
			return i
		}
	}
	return -1
}

// validateInstance enforces the model-③ rules:
//   - domain + key required; method in 0..5;
//   - key unique within a domain;
//   - a domain holding 2+ keys must use AEAD for ALL of them (XOR/None can't
//     be disambiguated by the server when several keys share a domain).
func validateInstance(list []Instance, in Instance, selfID string) error {
	domain, err := canonicalDomain(in.Domain)
	if err != nil {
		return err
	}
	if strings.TrimSpace(in.Key) == "" {
		return fmt.Errorf("ключ обязателен")
	}
	if in.Method < 0 || in.Method > 5 {
		return fmt.Errorf("некорректный метод шифрования")
	}

	var siblings []Instance
	for _, s := range list {
		if s.ID == selfID {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(s.Domain), domain) {
			siblings = append(siblings, s)
		}
	}
	for _, s := range siblings {
		if s.Key == in.Key {
			return fmt.Errorf("такой ключ уже используется на этом домене")
		}
	}
	if len(siblings) >= 1 {
		if !isAEADMethod(in.Method) {
			return fmt.Errorf("на домене с несколькими ключами требуется AEAD (ChaCha20 / AES-GCM)")
		}
		for _, s := range siblings {
			if !isAEADMethod(s.Method) {
				return fmt.Errorf("существующий ключ на этом домене использует не-AEAD метод — сначала переведите его на AEAD")
			}
		}
	}
	return nil
}
