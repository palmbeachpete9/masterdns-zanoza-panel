// Command zanoza-panel is a web manager for MasterDnsVPN instances with
// Zanoza (iOS) support. It supervises a single forked MasterDnsVPN server
// (per-domain keyring) and lets an admin mint domain+key instances and
// export them as zanoza:// links.
package main

import (
	"crypto/sha256"
	"crypto/tls"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

//go:embed web/dist
var embeddedWeb embed.FS

type server struct {
	cfg            *Config
	creds          *credentials
	mfa            *mfaStore
	mfaTickets     *mfaTicketStore
	sessions       *sessionStore
	limiter        *loginLimiter
	manager        *serverManager
	assets         map[string]cachedFile
	setup          *setupGate
	externalOrigin *url.URL // configured external origin behind a proxy (V4-03)
	trustedProxies []*net.IPNet
	useTLS         bool
	mu             sync.Mutex
	authMu         sync.RWMutex // orders password changes against in-flight logins
}

// cachedFile is an embedded static asset preloaded into shared memory once at
// startup, so serving it never re-reads/re-allocates the whole file per request.
type cachedFile struct {
	body        []byte
	contentType string
	etag        string
}

// buildAssetCache reads every embedded file once and computes a content ETag.
// The byte slices are shared read-only across all requests.
func buildAssetCache(root fs.FS) (map[string]cachedFile, error) {
	cache := map[string]cachedFile{}
	err := fs.WalkDir(root, ".", func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		if original, ok := conflictCopyOriginal(p); ok {
			if info, statErr := fs.Stat(root, original); statErr == nil && !info.IsDir() {
				return fmt.Errorf("embedded asset %q looks like a conflict copy of %q", p, original)
			}
		}
		body, err := fs.ReadFile(root, p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(body)
		cache[p] = cachedFile{
			body:        body,
			contentType: contentTypeFor(p),
			etag:        `"` + hex.EncodeToString(sum[:16]) + `"`,
		}
		return nil
	})
	return cache, err
}

func conflictCopyOriginal(name string) (string, bool) {
	dir := ""
	base := name
	if slash := strings.LastIndexByte(name, '/'); slash >= 0 {
		dir = name[:slash+1]
		base = name[slash+1:]
	}
	ext := ""
	if dot := strings.LastIndexByte(base, '.'); dot >= 0 {
		ext = base[dot:]
		base = base[:dot]
	}
	space := strings.LastIndexByte(base, ' ')
	if space <= 0 || space == len(base)-1 {
		return "", false
	}
	n, err := strconv.Atoi(base[space+1:])
	if err != nil || n <= 0 {
		return "", false
	}
	return dir + base[:space] + ext, true
}

func contentTypeFor(name string) string {
	switch {
	case strings.HasSuffix(name, ".html"):
		return "text/html; charset=utf-8"
	case strings.HasSuffix(name, ".js"):
		return "text/javascript; charset=utf-8"
	case strings.HasSuffix(name, ".css"):
		return "text/css; charset=utf-8"
	case strings.HasSuffix(name, ".svg"):
		return "image/svg+xml"
	case strings.HasSuffix(name, ".json"):
		return "application/json; charset=utf-8"
	default:
		return "application/octet-stream"
	}
}

func main() {
	configPath := flag.String("config", envDefault(EnvConfig, "/var/lib/zanoza-panel/config.json"), "path to panel config JSON")
	setCreds := flag.Bool("set-credentials", false, "set admin credentials (bcrypt) from -user and stdin, then exit")
	credUser := flag.String("user", "", "username for -set-credentials")
	passwordStdin := flag.Bool("password-stdin", false, "read the -set-credentials password from stdin")
	legacyCredPass := flag.String("password", "", "unsupported: passwords must be supplied with -password-stdin")
	mfaStatusFlag := flag.Bool("mfa-status", false, "print MFA status and exit")
	mfaSetupStartFlag := flag.Bool("mfa-setup-start", false, "start MFA setup and print the setup secret/URI")
	mfaSetupConfirmFlag := flag.Bool("mfa-setup-confirm", false, "confirm pending MFA setup using a code from stdin")
	mfaDisableFlag := flag.Bool("mfa-disable", false, "disable MFA and exit")
	mfaCodeStdin := flag.Bool("mfa-code-stdin", false, "read the MFA code from stdin")
	flag.Parse()
	configDir := filepath.Dir(*configPath)

	// Credential management subcommand: lets the installer and `zanoza
	// resetcreds` reuse the backend's bcrypt + atomic-persist path instead of
	// writing legacy SHA-256 in shell (F07/F24).
	if *setCreds {
		if *legacyCredPass != "" || !*passwordStdin {
			log.Fatalf("set credentials: use -password-stdin; command-line passwords are refused because they are visible in process listings")
		}
		credPass, err := readCredentialPassword(os.Stdin)
		if err != nil {
			log.Fatalf("read credentials password: %v", err)
		}
		creds := loadCredentials(filepath.Join(configDir, "panel.env"))
		if err := creds.set(*credUser, credPass); err != nil {
			log.Fatalf("set credentials: %v", err)
		}
		fmt.Println("credentials updated")
		return
	}

	if *mfaStatusFlag || *mfaSetupStartFlag || *mfaSetupConfirmFlag || *mfaDisableFlag {
		creds := loadCredentials(filepath.Join(configDir, "panel.env"))
		if err := creds.loadError(); err != nil {
			log.Fatalf("credentials: %v", err)
		}
		mfa := loadMFAStore(filepath.Join(configDir, "mfa.json"))
		if err := mfa.loadError(); err != nil {
			log.Fatalf("MFA: %v", err)
		}
		switch {
		case *mfaStatusFlag:
			if mfa.status().Enabled {
				fmt.Println("enabled")
			} else {
				fmt.Println("disabled")
			}
		case *mfaSetupStartFlag:
			view, err := mfa.startSetup(creds.username())
			if err != nil {
				log.Fatalf("MFA setup: %v", err)
			}
			fmt.Printf("Секрет: %s\n", view.Secret)
			fmt.Printf("URI: %s\n", view.OtpauthURL)
		case *mfaSetupConfirmFlag:
			if !*mfaCodeStdin {
				log.Fatalf("MFA setup confirm: use -mfa-code-stdin")
			}
			code, err := readMFACode(os.Stdin)
			if err != nil {
				log.Fatalf("MFA code: %v", err)
			}
			if err := mfa.forceConfirmSetup(code); err != nil {
				log.Fatalf("MFA setup confirm: %v", err)
			}
			fmt.Println("MFA enabled")
		case *mfaDisableFlag:
			if err := mfa.forceDisable(); err != nil {
				log.Fatalf("MFA disable: %v", err)
			}
			fmt.Println("MFA disabled")
		}
		return
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	if err := applyEnvOverrides(cfg); err != nil {
		log.Fatalf("invalid environment override: %v", err)
	}
	if err := cfg.validateRuntime(); err != nil {
		log.Fatalf("invalid effective config: %v", err)
	}

	creds := loadCredentials(filepath.Join(configDir, "panel.env"))
	// Fail closed: if panel.env exists but is unreadable/malformed, do NOT start
	// (a transient read error must never reopen unauthenticated setup) (V4-02).
	if err := creds.loadError(); err != nil {
		log.Fatalf("credentials: %v (refusing to start; fix or run `zanoza resetcreds`)", err)
	}
	maybeAutoSetup(creds)
	mfa := loadMFAStore(filepath.Join(configDir, "mfa.json"))
	if err := mfa.loadError(); err != nil {
		log.Fatalf("MFA: %v (refusing to start; fix or run `zanoza mfa disable`)", err)
	}
	manager := newServerManager(envDefault(EnvRuntimeDir, filepath.Join(configDir, "masterdns")))

	webRoot, err := fs.Sub(embeddedWeb, "web/dist")
	if err != nil {
		log.Fatalf("embed web: %v", err)
	}
	assets, err := buildAssetCache(webRoot)
	if err != nil {
		log.Fatalf("embed web cache: %v", err)
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

	// Optional external origin (TLS-terminating reverse proxy) — origin checks
	// and cookie security derive from it when set (V4-03).
	var externalOrigin *url.URL
	if v := os.Getenv(EnvExternalOrigin); v != "" {
		u, perr := parseExternalOrigin(v)
		if perr != nil {
			log.Fatalf("invalid %s=%q (want scheme://host[:port])", EnvExternalOrigin, v)
		}
		externalOrigin = u
	}
	trustedProxies, err := parseTrustedProxies(os.Getenv(EnvTrustedProxies))
	if err != nil {
		log.Fatalf("invalid %s: %v", EnvTrustedProxies, err)
	}

	// One-time bootstrap token for first-run setup (DNS-rebinding defence, V4-03).
	setupGate, err := newSetupGate(configDir, creds.setupRequired())
	if err != nil {
		log.Fatalf("setup token: %v", err)
	}
	if tok := setupGate.logToken(); tok != "" {
		log.Printf("FIRST-RUN SETUP TOKEN: %s  (also at %s)", tok, filepath.Join(configDir, "setup.token"))
	}

	srv := &server{
		cfg:            cfg,
		creds:          creds,
		mfa:            mfa,
		mfaTickets:     newMFATicketStore(),
		sessions:       newSessionStore(),
		limiter:        newLoginLimiter(8, 5*time.Minute),
		manager:        manager,
		assets:         assets,
		setup:          setupGate,
		externalOrigin: externalOrigin,
		trustedProxies: trustedProxies,
		useTLS:         useTLS,
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
			reloaded, err := loadExistingConfig(*configPath)
			if err != nil {
				log.Printf("reload config failed: %v", err)
				continue
			}
			if err := applyEnvOverrides(reloaded); err != nil {
				log.Printf("reload environment override failed: %v", err)
				continue
			}
			if err := reloaded.validateRuntime(); err != nil {
				log.Printf("reload effective config failed: %v", err)
				continue
			}
			if err := validateHotReload(srv.config(), reloaded); err != nil {
				log.Printf("reload config failed: %v", err)
				continue
			}
			// Publish in place under the commit coordinator so reload can't
			// interleave with an HTTP mutation, and s.cfg identity stays
			// stable (no stale-pointer handler) (F13).
			srv.config().publishReload(reloaded)
			if err := manager.apply(srv.config().snapshot()); err != nil {
				log.Printf("reload apply failed: %v", err)
				continue
			}
			log.Printf("reloaded config")
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.route)

	addr := net.JoinHostPort(cfg.PanelAddr, strconv.Itoa(cfg.PanelPort))
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

func validateHotReload(current, reloaded *Config) error {
	before := current.Meta()
	after := reloaded.Meta()
	if before.PanelAddr != after.PanelAddr || before.PanelPort != after.PanelPort ||
		before.TLSCert != after.TLSCert || before.TLSKey != after.TLSKey {
		return fmt.Errorf("panel listener or TLS settings changed; restart is required")
	}
	return nil
}

func isLoopbackAddr(addr string) bool {
	if ip := net.ParseIP(addr); ip != nil {
		return ip.IsLoopback()
	}
	// Hostnames, including "localhost", are not trusted here: a poisoned hosts
	// file or resolver result could make a hostname bind a non-loopback address
	// while bypassing the plaintext-public-listener guard.
	return false
}

func parseExternalOrigin(value string) (*url.URL, error) {
	u, err := url.Parse(value)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" ||
		u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("invalid external origin")
	}
	return u, nil
}

// route dispatches by the configured panel path; everything outside it is a
// decoy 404 so the admin surface stays hidden.
func (s *server) route(w http.ResponseWriter, r *http.Request) {
	// Baseline security headers on every response (N04).
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Content-Security-Policy", "frame-ancestors 'none'")
	h.Set("Referrer-Policy", "no-referrer")
	if s.cookieSecure() {
		h.Set("Strict-Transport-Security", "max-age=31536000")
	}

	// Read PanelPath through the config lock (cfg.Meta), not s.mu, since
	// publishReload mutates it under cfg.mu — reading under s.mu was a race (R-01).
	path := s.config().Meta().PanelPath

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
	f, ok := s.assets["index.html"]
	if !ok {
		http.Error(w, "index missing", http.StatusInternalServerError)
		return
	}
	// Shared cached bytes: no per-request file read/allocation.
	w.Header().Set("Content-Type", f.contentType)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(f.body)
}

func (s *server) serveAsset(w http.ResponseWriter, r *http.Request, rest string) {
	f, ok := s.assets[rest]
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", f.contentType)
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Header().Set("ETag", f.etag)
	// Revalidation: an unchanged asset returns 304 with no body, so a polling
	// browser neither re-downloads nor makes the server re-serve the bytes.
	if r.Header.Get("If-None-Match") == f.etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	_, _ = w.Write(f.body)
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
	case "auth/mfa/verify":
		s.handleAuthMFAVerify(w, r)
	case "auth/mfa/setup/start":
		s.handleAuthMFASetupStart(w, r)
	case "auth/mfa/setup/confirm":
		s.handleAuthMFASetupConfirm(w, r)
	case "auth/mfa/skip":
		s.handleAuthMFASkip(w, r)
	case "auth/mfa/disable":
		s.requireAuth(w, r, s.handleAuthMFADisable)
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
	w.Header().Set("Cache-Control", "no-store") // authenticated API data is never cached (N04)
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
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return errBodyTooLarge{err}
		}
		return err
	}
	return decodeStrictJSONObject(raw, v)
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
func remoteIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func parseTrustedProxies(value string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if ip := net.ParseIP(item); ip != nil {
			bits := 128
			if ip.To4() != nil {
				bits = 32
			}
			out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		_, network, err := net.ParseCIDR(item)
		if err != nil {
			return nil, fmt.Errorf("%q is not an IP address or CIDR", item)
		}
		out = append(out, network)
	}
	return out, nil
}

func (s *server) isTrustedProxy(ip net.IP) bool {
	for _, network := range s.trustedProxies {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// clientIP uses forwarding headers only when the direct peer is explicitly
// trusted. Walking right-to-left prevents an external client from prepending a
// spoofed address to a proxy-maintained chain.
func (s *server) clientIP(r *http.Request) string {
	direct := remoteIP(r)
	if !s.isTrustedProxy(net.ParseIP(direct)) {
		return direct
	}
	chain := r.Header.Values("X-Forwarded-For")
	if len(chain) == 0 {
		return direct
	}
	var hops []string
	for _, value := range chain {
		for _, hop := range strings.Split(value, ",") {
			if hop = strings.TrimSpace(hop); hop != "" {
				hops = append(hops, hop)
			}
		}
	}
	for i := len(hops) - 1; i >= 0; i-- {
		ip := net.ParseIP(hops[i])
		if ip == nil {
			return direct
		}
		if !s.isTrustedProxy(ip) {
			return ip.String()
		}
	}
	return direct
}

func (s *server) requireAuth(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	if !s.authenticated(r) {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	// CSRF defence: reject cross-origin state-changing requests (N04).
	if isMutatingMethod(r.Method) && !s.sameOriginOK(r) {
		writeErr(w, http.StatusForbidden, "cross-origin request rejected")
		return
	}
	next(w, r)
}

func isMutatingMethod(m string) bool {
	switch m {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

// expectedScheme is derived from the actual TLS listener, never from untrusted
// forwarding headers (R-02).
func (s *server) expectedScheme() string {
	if s.useTLS {
		return "https"
	}
	return "http"
}

// sameOriginOK accepts a request that carries no Origin (non-browser client) or
// an Origin whose scheme, host and port exactly match the panel's own. Browsers
// always send Origin on cross-origin requests, so a mismatch is a CSRF attempt.
// The scheme is now compared too (R-02/N04).
func (s *server) sameOriginOK(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	return s.originMatches(origin, r.Host)
}

// strictSameOrigin additionally REQUIRES the Origin header to be present and
// matching — used for unauthenticated first-run setup, where a missing/mismatched
// browser origin must be rejected (R-02).
func (s *server) strictSameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	return s.originMatches(origin, r.Host)
}

func hasJSONContentType(r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.EqualFold(strings.TrimSpace(ct), "application/json")
}

func (s *server) originMatches(origin, host string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") ||
		u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	// When an external origin is configured (reverse proxy), validate against it
	// exactly and ignore the (proxy-supplied) Host — supporting HTTPS-terminating
	// proxies while still defeating rebinding (V4-03).
	if s.externalOrigin != nil {
		return strings.EqualFold(u.Scheme, s.externalOrigin.Scheme) &&
			strings.EqualFold(u.Host, s.externalOrigin.Host)
	}
	if !strings.EqualFold(u.Scheme, s.expectedScheme()) {
		return false
	}
	return strings.EqualFold(u.Host, host)
}

// cookieSecure marks session cookies Secure when the externally-visible origin
// is HTTPS (e.g. a TLS-terminating proxy), not merely when the internal listener
// is TLS (V4-03).
func (s *server) cookieSecure() bool {
	if s.externalOrigin != nil {
		return s.externalOrigin.Scheme == "https"
	}
	return s.useTLS
}

func (s *server) setSessionCookie(w http.ResponseWriter, token string) {
	path := s.config().Meta().PanelPath // cfg.mu-protected read (R-01)
	maxAge := 12 * 3600
	if token == "" {
		maxAge = -1 // expire immediately on logout
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     path,
		HttpOnly: true,
		Secure:   s.cookieSecure(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	})
}

func (s *server) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"authenticated":  s.authenticated(r),
		"setup_required": s.creds.setupRequired(),
		"mfa_enabled":    s.mfa.status().Enabled,
	})
}

func (s *server) handleAuthSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	// First-run setup is unauthenticated, so CSRF protection must be applied
	// here directly (it does not pass through requireAuth): require an exact
	// same-origin browser request, and a JSON content type to force a CORS
	// preflight for cross-origin attempts (R-02).
	if s.setup == nil || !s.setup.required() || !s.strictSameOrigin(r) || !hasJSONContentType(r) {
		writeErr(w, http.StatusForbidden, "cross-origin request rejected")
		return
	}
	if !s.creds.setupRequired() {
		writeErr(w, http.StatusForbidden, "уже настроено")
		return
	}
	var body struct {
		User, Password, Token string
	}
	if err := readJSON(w, r, &body); err != nil {
		writeBadBody(w, err)
		return
	}
	// One-time bootstrap token: same-origin alone cannot stop DNS rebinding from
	// claiming a fresh loopback panel, so a locally-printed token is required and
	// consumed exactly once (V4-03).
	if !s.setup.check(body.Token) {
		writeErr(w, http.StatusForbidden, "invalid or missing setup token")
		return
	}
	// createInitial is the single transactional bootstrap: concurrent setup
	// requests resolve to exactly one owner (F03).
	if err := s.creds.createInitial(strings.TrimSpace(body.User), body.Password); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.setup.consume()
	ticket, err := s.mfaTickets.create(mfaTicketSetup)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "MFA setup error")
		return
	}
	writeJSON(w, map[string]any{"ok": true, "mfa_setup_required": true, "ticket": ticket})
}

func (s *server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.sameOriginOK(r) {
		writeErr(w, http.StatusForbidden, "cross-origin request rejected")
		return
	}
	var body struct{ User, Password string }
	if err := readJSON(w, r, &body); err != nil {
		writeBadBody(w, err)
		return
	}
	limitKey := s.clientIP(r)
	if !s.limiter.allowed(limitKey) {
		writeErr(w, http.StatusTooManyRequests, "слишком много попыток, попробуйте позже")
		return
	}
	defer s.limiter.release(limitKey)
	// A password change takes the write side of authMu through credential
	// replacement and session revocation. Holding the read side through session
	// creation prevents an old-password login from minting a session just after
	// the password-change handler revoked existing sessions.
	s.authMu.RLock()
	defer s.authMu.RUnlock()
	if !s.creds.verify(strings.TrimSpace(body.User), body.Password) {
		s.limiter.fail(limitKey)
		writeErr(w, http.StatusUnauthorized, "неверный логин или пароль")
		return
	}
	s.limiter.reset(limitKey)
	if !s.mfaLoginResponse(w) {
		return
	}
	s.issueSession(w)
}

func (s *server) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	// POST-only: a top-level GET navigation must not be able to revoke a
	// session (SameSite=Lax would still send the cookie on GET) (N04).
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
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
	limitKey := "password:" + s.clientIP(r)
	if !s.limiter.allowed(limitKey) {
		writeErr(w, http.StatusTooManyRequests, "слишком много попыток, попробуйте позже")
		return
	}
	defer s.limiter.release(limitKey)

	s.authMu.Lock()
	defer s.authMu.Unlock()
	matched, err := s.creds.changePassword(body.Current, body.Password)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if !matched {
		s.limiter.fail(limitKey)
		writeErr(w, http.StatusForbidden, "текущий пароль неверен")
		return
	}
	s.limiter.reset(limitKey)
	// A password change invalidates every existing session (F07).
	s.sessions.revokeAll()
	s.mfaTickets.revokeAll()
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
			"mfa":        s.mfa.status(),
		})
	case http.MethodPut:
		var body struct{ Name string }
		if err := readJSON(w, r, &body); err != nil {
			writeBadBody(w, err)
			return
		}
		name := strings.TrimSpace(body.Name)
		if err := cfg.commit(func(work *Config) error {
			if name != "" {
				work.Name = name
			}
			return nil
		}); err != nil {
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
	in.Key = strings.TrimSpace(in.Key)
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
			updated.Key = strings.TrimSpace(in.Key)
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

// mutateInstances transactionally applies fn to the instance list: the change
// is validated + persisted on a clone, and only published to live state after
// the durable write succeeds (F13). The keyring is then re-applied to the
// running server.
func (s *server) mutateInstances(fn func([]Instance) ([]Instance, error)) error {
	cfg := s.config()
	if err := cfg.commit(func(work *Config) error {
		next, err := fn(work.Instances)
		if err != nil {
			return err
		}
		work.Instances = next
		// Validate the complete proposed list (IDs, canonical domains, multi-key
		// rules) inside the transaction before it is persisted (R-05).
		return work.canonicalizeAndValidateInstances()
	}); err != nil {
		return err
	}
	// Config is the source of truth and is durably persisted. A failure to
	// (re)start/reload the MasterDnsVPN server (e.g. binary missing on a dev
	// box) must NOT roll back the CRUD operation — it surfaces separately via
	// state.server.exit_error / apply_error.
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
	key := strings.TrimSpace(in.Key)
	if key == "" {
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
		if strings.TrimSpace(s.Key) == key {
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
