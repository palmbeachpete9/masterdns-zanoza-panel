package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestStaleAppliedMarkerDoesNotHideStartFailure(t *testing.T) {
	m := newServerManager(t.TempDir())
	instances := []Instance{{Domain: "v.example.com", Key: "k", Method: 5}}
	if err := m.writeKeyring(instances); err != nil {
		t.Fatal(err)
	}
	if err := writeTestAppliedMarker(m.keyringPath, m.desiredDigest, m.desiredGen); err != nil {
		t.Fatal(err)
	}
	m.binary = filepath.Join(t.TempDir(), "missing-masterdns")
	if err := m.apply(instances); err == nil {
		t.Fatal("expected apply/start failure")
	}
	if state := m.state(); state.ApplyError == "" {
		t.Fatalf("stale matching marker hid current apply failure: %+v", state)
	}
}

func TestTrustedProxyClientsHaveIndependentLoginLimitKeys(t *testing.T) {
	proxies, err := parseTrustedProxies("127.0.0.1/32")
	if err != nil {
		t.Fatal(err)
	}
	s := &server{trustedProxies: proxies}
	first := &http.Request{RemoteAddr: "127.0.0.1:41001", Header: http.Header{"X-Forwarded-For": {"198.51.100.10"}}}
	second := &http.Request{RemoteAddr: "127.0.0.1:41002", Header: http.Header{"X-Forwarded-For": {"198.51.100.11"}}}
	if s.clientIP(first) == s.clientIP(second) {
		t.Fatalf("proxied clients share rate-limit key %q", s.clientIP(first))
	}
}

func TestUntrustedPeerCannotSpoofForwardedClient(t *testing.T) {
	s := &server{}
	r := &http.Request{RemoteAddr: "203.0.113.7:41001", Header: http.Header{"X-Forwarded-For": {"198.51.100.10"}}}
	if got := s.clientIP(r); got != "203.0.113.7" {
		t.Fatalf("untrusted forwarding header changed client IP: %q", got)
	}
}

func TestAcceptedIPv6LoopbackProducesUsableListenAddress(t *testing.T) {
	if !isLoopbackAddr("::1") {
		t.Fatal("::1 must be accepted as loopback")
	}
	addr := net.JoinHostPort("::1", "0")
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listen %q: %v", addr, err)
	}
	_ = listener.Close()
	if got := fmt.Sprintf("http://%s/", addr); got != "http://[::1]:0/" {
		t.Fatalf("unexpected IPv6 URL: %q", got)
	}
}

func TestLoopbackPlaintextGuardRejectsHostnames(t *testing.T) {
	if isLoopbackAddr("localhost") {
		t.Fatal("hostname was trusted as a literal loopback bind")
	}
	if isLoopbackAddr("") {
		t.Fatal("empty bind address was trusted as loopback")
	}
	if !isLoopbackAddr("127.0.0.1") || !isLoopbackAddr("::1") {
		t.Fatal("literal loopback address was rejected")
	}
}

func TestAppliedMarkerRequiresCurrentGeneration(t *testing.T) {
	m := newServerManager(t.TempDir())
	if err := m.writeKeyring([]Instance{{Domain: "v.example.com", Key: "k", Method: 5}}); err != nil {
		t.Fatal(err)
	}
	m.cmd = &exec.Cmd{}
	m.pid = os.Getpid()
	if err := writeTestAppliedMarker(m.keyringPath, m.desiredDigest, m.desiredGen-1); err != nil {
		t.Fatal(err)
	}
	if state := m.state(); !state.ApplyPending {
		t.Fatalf("old generation was accepted: %+v", state)
	}
}

func TestManagerRestartNeverReusesAppliedGeneration(t *testing.T) {
	dir := t.TempDir()
	instances := []Instance{{Domain: "v.example.com", Key: "k", Method: 5}}
	first := newServerManager(dir)
	if err := first.writeKeyring(instances); err != nil {
		t.Fatal(err)
	}
	if err := writeTestAppliedMarker(first.keyringPath, first.desiredDigest, first.desiredGen); err != nil {
		t.Fatal(err)
	}

	restarted := newServerManager(dir)
	if err := restarted.writeKeyring(instances); err != nil {
		t.Fatal(err)
	}
	if restarted.desiredGen <= first.desiredGen {
		t.Fatalf("generation reused across restart: old=%d new=%d", first.desiredGen, restarted.desiredGen)
	}
	if state := restarted.state(); state.AppliedKeyring == restarted.desiredDigest {
		t.Fatalf("stale marker matched a new post-restart write: %+v", state)
	}
}

func TestGenerationWatermarkIgnoresMarkerForDifferentKeyring(t *testing.T) {
	m := newServerManager(t.TempDir())
	if err := m.writeKeyring([]Instance{{Domain: "v.example.com", Key: "k", Method: 5}}); err != nil {
		t.Fatal(err)
	}
	want := m.desiredGen
	if err := writeTestAppliedMarker(m.keyringPath, "different-digest", math.MaxUint64); err != nil {
		t.Fatal(err)
	}
	if got := readGenerationWatermark(m.keyringPath); got != want {
		t.Fatalf("watermark trusted unrelated marker: got=%d want=%d", got, want)
	}
}

func TestInvalidEnvironmentOverridesFailClosed(t *testing.T) {
	for key, value := range map[string]string{
		EnvPanelPort: "0",
		EnvPanelPath: "/admin/nested",
	} {
		t.Run(key, func(t *testing.T) {
			t.Setenv(key, value)
			if err := applyEnvOverrides(defaultConfig()); err == nil {
				t.Fatalf("invalid explicit override %s=%q was ignored", key, value)
			}
		})
	}
}

func TestExternalOriginRejectsNonOriginComponents(t *testing.T) {
	for _, value := range []string{
		"https://user@example.com",
		"https://example.com/admin",
		"https://example.com?x=1",
		"https://example.com/#fragment",
		"ftp://example.com",
	} {
		if _, err := parseExternalOrigin(value); err == nil {
			t.Fatalf("accepted non-origin value %q", value)
		}
	}
	if _, err := parseExternalOrigin("https://example.com:8443"); err != nil {
		t.Fatalf("rejected valid external origin: %v", err)
	}
}

func TestReloadMissingConfigDoesNotCreateReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if _, err := loadExistingConfig(path); !os.IsNotExist(err) {
		t.Fatalf("missing reload config error = %v, want os.ErrNotExist", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("reload created replacement config: %v", err)
	}
}

func TestLoadExistingConfigDoesNotUseCreatingLoadPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	cfg := defaultConfig()
	cfg.path = path
	if err := cfg.save(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	if _, err := loadExistingConfig(path); !os.IsNotExist(err) {
		t.Fatalf("missing reload config error = %v, want os.ErrNotExist", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("reload recreated deleted config: %v", err)
	}
}

func TestEnsureServerConfigRejectsUnsafeExistingPath(t *testing.T) {
	t.Run("directory", func(t *testing.T) {
		m := newServerManager(t.TempDir())
		if err := os.MkdirAll(m.configPath, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := m.ensureServerConfig(); err == nil {
			t.Fatal("existing directory was accepted as server config")
		}
	})

	t.Run("symlink", func(t *testing.T) {
		m := newServerManager(t.TempDir())
		target := filepath.Join(t.TempDir(), "target.toml")
		if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, m.configPath); err != nil {
			t.Fatal(err)
		}
		if err := m.ensureServerConfig(); err == nil {
			t.Fatal("existing symlink was accepted as server config")
		}
	})
}

func TestAutoRestartLaunchFailuresExhaustBoundedBudget(t *testing.T) {
	m := newServerManager(t.TempDir())
	m.binary = filepath.Join(t.TempDir(), "missing-masterdns")
	m.restartDelay = time.Millisecond
	m.desiredUp = true
	m.restarts = 1
	m.windowAt = time.Now()
	m.scheduleAutoRestart(fmt.Errorf("test process exit"), m.restartDelay)

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		m.mu.Lock()
		desiredUp := m.desiredUp
		lastErr := m.lastApplyErr
		m.mu.Unlock()
		if !desiredUp {
			if !strings.Contains(lastErr, "restart launch loop") {
				t.Fatalf("unexpected terminal restart error: %q", lastErr)
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("launch failures left supervision pending forever")
}

func TestStopReturnsWhenReaperDoesNotCloseDone(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Skipf("sleep command unavailable: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		waitDone := make(chan struct{})
		go func() {
			_ = cmd.Wait()
			close(waitDone)
		}()
		select {
		case <-waitDone:
		case <-time.After(time.Second):
			t.Fatalf("timed out reaping test child pid %d", cmd.Process.Pid)
		}
	}()

	m := newServerManager(t.TempDir())
	m.cmd = cmd
	m.pid = cmd.Process.Pid
	m.done = make(chan struct{})

	started := time.Now()
	err := m.stopWithTimeout(5*time.Millisecond, 5*time.Millisecond)
	if err == nil {
		t.Fatal("expected stop timeout when reaper completion channel never closes")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("stop blocked too long after kill escalation: %s", elapsed)
	}
	if state := m.state(); !strings.Contains(state.ApplyError, "stop timed out") {
		t.Fatalf("stop timeout was not surfaced in state: %+v", state)
	}
}

func TestLoadConfigRejectsInvalidRuntimeSettings(t *testing.T) {
	for name, fields := range map[string]string{
		"invalid path": `"panel_path":"/admin/nested","panel_port":8443`,
		"invalid port": `"panel_path":"/admin","panel_port":0`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			body := `{"version":1,"name":"x","panel_addr":"127.0.0.1",` + fields + `,"instances":[]}`
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadConfig(path); err == nil {
				t.Fatal("invalid runtime config was silently normalized")
			}
		})
	}
}

func TestLoadConfigRejectsUnknownDuplicateAndNonObjectJSON(t *testing.T) {
	for name, body := range map[string]string{
		"unknown setting":   `{"version":1,"name":"x","panel_addr":"127.0.0.1","panel_port":8443,"panel_path":"/admin","panel_por":9443,"instances":[]}`,
		"duplicate setting": `{"version":1,"name":"x","panel_addr":"127.0.0.1","panel_port":8443,"panel_port":9443,"panel_path":"/admin","instances":[]}`,
		"nested duplicate":  `{"version":1,"name":"x","panel_addr":"127.0.0.1","panel_port":8443,"panel_path":"/admin","instances":[{"id":"x","domain":"v.example.com","key":"a","key":"b","method":5}]}`,
		"non-object":        `null`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadConfig(path); err == nil {
				t.Fatal("ambiguous or unknown config JSON was accepted")
			}
		})
	}
}

func TestLoginLimiterDoesNotEvictActiveLockoutsAtCapacity(t *testing.T) {
	limiter := newLoginLimiter(1, time.Hour)
	limiter.cap = 2
	limiter.fail("198.51.100.1")
	limiter.fail("198.51.100.2")

	if limiter.allowed("198.51.100.1") {
		t.Fatal("active lockout was not enforced")
	}
	if limiter.allowed("198.51.100.3") {
		t.Fatal("new source was allowed by evicting an active lockout")
	}
	if limiter.allowed("198.51.100.1") {
		t.Fatal("capacity pressure evicted the existing active lockout")
	}
}

func TestLoginLimiterDoesNotEvictRecentFailureCountsAtCapacity(t *testing.T) {
	limiter := newLoginLimiter(3, time.Hour)
	limiter.cap = 2
	limiter.fail("198.51.100.1")
	limiter.fail("198.51.100.2")

	if limiter.allowed("198.51.100.3") {
		t.Fatal("new source was allowed by evicting a recent failure record")
	}
	limiter.fail("198.51.100.1")
	limiter.fail("198.51.100.1")
	if limiter.allowed("198.51.100.1") {
		t.Fatal("capacity pressure reset the existing source failure count")
	}
}

func TestLoginLimiterBoundsConcurrentPasswordChecks(t *testing.T) {
	limiter := newLoginLimiter(8, time.Hour)
	if !limiter.allowed("198.51.100.1") {
		t.Fatal("first password check was rejected")
	}
	if limiter.allowed("198.51.100.1") {
		t.Fatal("concurrent password check from one source bypassed the limiter")
	}

	limiter.maxInflight = 2
	if !limiter.allowed("198.51.100.2") {
		t.Fatal("second global password check was rejected")
	}
	if limiter.allowed("198.51.100.3") {
		t.Fatal("global password-check concurrency ceiling was bypassed")
	}

	limiter.fail("198.51.100.1")
	if !limiter.allowed("198.51.100.3") {
		t.Fatal("released password-check slot was not reusable")
	}
	limiter.release("198.51.100.2")
	limiter.release("198.51.100.3")
	if limiter.inflight != 0 {
		t.Fatalf("password-check slots leaked: %d", limiter.inflight)
	}
}

func TestCredentialsFailClosedOnScannerError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "panel.env")
	body := "ZANOZA_PANEL_USER='admin'\nZANOZA_PANEL_PASS_BCRYPT='$2a$12$invalid'\n#" +
		strings.Repeat("x", 70*1024)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	creds := loadCredentials(path)
	if creds.loadError() == nil || creds.setupRequired() {
		t.Fatal("scanner failure must fail closed even after usable-looking lines")
	}
}

func TestCredentialsFailClosedBeforeReadingOversizedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "panel.env")
	body := strings.Repeat("x", maxCredentialFileBytes+1)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	creds := loadCredentials(path)
	if creds.loadError() == nil || creds.setupRequired() {
		t.Fatal("oversized credential file must fail closed")
	}
}

func TestCredentialsRejectMalformedAndDuplicateCredentialValues(t *testing.T) {
	for name, body := range map[string]string{
		"malformed line": "ZANOZA_PANEL_USER='admin'\nnot-an-assignment\nZANOZA_PANEL_PASS_BCRYPT='$2a$12$invalid'\n",
		"duplicate user": "ZANOZA_PANEL_USER='admin'\nZANOZA_PANEL_USER='other'\nZANOZA_PANEL_PASS_BCRYPT='$2a$12$invalid'\n",
		"invalid bcrypt": "ZANOZA_PANEL_USER='admin'\nZANOZA_PANEL_PASS_BCRYPT='$2a$12$invalid'\n",
		"invalid legacy": "ZANOZA_PANEL_USER='admin'\nZANOZA_PANEL_SALT='salt'\nZANOZA_PANEL_PASS_HASH='not-a-sha256'\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "panel.env")
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			creds := loadCredentials(path)
			if creds.loadError() == nil || creds.setupRequired() {
				t.Fatal("malformed credentials did not fail closed")
			}
		})
	}
}

func TestCredentialsRejectExcessiveBcryptCost(t *testing.T) {
	path := filepath.Join(t.TempDir(), "panel.env")
	hash := "$2a$31$" + strings.Repeat("a", 53)
	body := "ZANOZA_PANEL_USER='admin'\nZANOZA_PANEL_PASS_BCRYPT='" + hash + "'\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := loadCredentials(path).loadError(); err == nil {
		t.Fatal("credential file with excessive bcrypt cost was accepted")
	}
}

func TestCredentialsTightenExistingFileMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "panel.env")
	hash := "$2a$12$LQv3c1yqBWG7HJLvZixlGeqMPbZlEwPVF3L6OPMnTjSsHh4H1Q2eK"
	body := "ZANOZA_PANEL_USER='admin'\nZANOZA_PANEL_PASS_BCRYPT='" + hash + "'\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := loadCredentials(path).loadError(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("credential mode = %o, want 600", got)
	}
}

func TestCredentialsRejectUnmatchedQuotes(t *testing.T) {
	for _, body := range []string{
		"ZANOZA_PANEL_USER='admin\nZANOZA_PANEL_PASS_BCRYPT='$2a$12$LQv3c1yqBWG7HJLvZixlGeqMPbZlEwPVF3L6OPMnTjSsHh4H1Q2eK'\n",
		"ZANOZA_PANEL_USER=admin'\nZANOZA_PANEL_PASS_BCRYPT='$2a$12$LQv3c1yqBWG7HJLvZixlGeqMPbZlEwPVF3L6OPMnTjSsHh4H1Q2eK'\n",
	} {
		path := filepath.Join(t.TempDir(), "panel.env")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := loadCredentials(path).loadError(); err == nil {
			t.Fatal("credential file with unmatched quote was accepted")
		}
	}
}

func TestPanelConfigRejectsUnsupportedVersion(t *testing.T) {
	for name, versionField := range map[string]string{
		"missing": "",
		"zero":    `"version":0,`,
		"future":  `"version":2,`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			body := `{` + versionField + `"panel_addr":"127.0.0.1","panel_port":8443,"panel_path":"/admin","instances":[]}`
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadExistingConfig(path); err == nil {
				t.Fatal("missing or unsupported panel config version was accepted")
			}
		})
	}
}

func TestHotReloadRejectsListenerAndTLSChanges(t *testing.T) {
	current := defaultConfig()
	for name, mutate := range map[string]func(*Config){
		"address": func(cfg *Config) { cfg.PanelAddr = "127.0.0.2" },
		"port":    func(cfg *Config) { cfg.PanelPort++ },
		"cert":    func(cfg *Config) { cfg.TLSCert = "/new/cert" },
		"key":     func(cfg *Config) { cfg.TLSKey = "/new/key" },
	} {
		t.Run(name, func(t *testing.T) {
			reloaded := defaultConfig()
			mutate(reloaded)
			if err := validateHotReload(current, reloaded); err == nil {
				t.Fatal("listener/TLS change was accepted for hot reload")
			}
		})
	}

	reloaded := defaultConfig()
	reloaded.Name = "renamed"
	reloaded.PanelPath = "/new-path"
	if err := validateHotReload(current, reloaded); err != nil {
		t.Fatalf("safe live settings rejected: %v", err)
	}
}

func TestConfigRejectsExcessiveInstanceCount(t *testing.T) {
	cfg := defaultConfig()
	cfg.Instances = make([]Instance, maxInstances+1)
	if err := cfg.canonicalizeAndValidateInstances(); err == nil {
		t.Fatal("excessive instance count was accepted")
	}
}

func TestInstanceKeysUseMasterDNSCanonicalWhitespaceForm(t *testing.T) {
	cfg := defaultConfig()
	cfg.Instances = []Instance{{
		ID:     " first ",
		Domain: " V.Example.com. ",
		Key:    "  shared-secret\t",
		Method: 5,
	}}
	if err := cfg.canonicalizeAndValidateInstances(); err != nil {
		t.Fatal(err)
	}
	got := cfg.Instances[0]
	if got.ID != "first" || got.Domain != "v.example.com" || got.Key != "shared-secret" {
		t.Fatalf("instance was not canonicalized: %#v", got)
	}

	payload := strings.TrimPrefix(zanozaLink(got), "zanoza://profile?data=")
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		t.Fatal(err)
	}
	var profile sharedProfilePayload
	if err := json.Unmarshal(raw, &profile); err != nil {
		t.Fatal(err)
	}
	if profile.EncryptionKey != "shared-secret" {
		t.Fatalf("profile shared non-canonical key %q", profile.EncryptionKey)
	}
}

func TestInstanceKeysRejectWhitespaceCanonicalDuplicates(t *testing.T) {
	cfg := defaultConfig()
	cfg.Instances = []Instance{
		{ID: "a", Domain: "v.example.com", Key: "shared-secret", Method: 5},
		{ID: "b", Domain: "v.example.com", Key: " shared-secret ", Method: 5},
	}
	if err := cfg.canonicalizeAndValidateInstances(); err == nil {
		t.Fatal("keys that MasterDNS canonicalizes to the same value were accepted")
	}
}

func TestMalformedCredentialsCannotBeReplacedThroughSetup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "panel.env")
	if err := os.WriteFile(path, []byte("malformed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	creds := loadCredentials(path)
	if err := creds.createInitial("admin", "longenough1"); err == nil {
		t.Fatal("malformed existing credentials were replaced through first-run setup")
	}
}

func TestSetupEndpointRequiresActiveSetupGate(t *testing.T) {
	s := newTestServer(t)
	s.setup.consume()
	body := `{"user":"adminuser","password":"longenough1","token":""}`
	r := httptest.NewRequest(http.MethodPost, "http://panel.local/admin/api/auth/setup", strings.NewReader(body))
	r.Host = "panel.local"
	r.Header.Set("Origin", "http://panel.local")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handleAuthSetup(w, r)
	if w.Code != http.StatusForbidden || !s.creds.setupRequired() {
		t.Fatalf("closed setup gate returned %d or changed credentials", w.Code)
	}
}

func TestConcurrentPasswordChangesCannotBothUseOldPassword(t *testing.T) {
	creds := loadCredentials(filepath.Join(t.TempDir(), "panel.env"))
	if err := creds.set("admin", "oldpassword"); err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	var successes int
	var mu sync.Mutex
	for _, password := range []string{"newpassword1", "newpassword2"} {
		wg.Add(1)
		go func(password string) {
			defer wg.Done()
			<-start
			matched, err := creds.changePassword("oldpassword", password)
			if err != nil {
				t.Errorf("change password: %v", err)
				return
			}
			if matched {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}(password)
	}
	close(start)
	wg.Wait()

	if successes != 1 {
		t.Fatalf("old password changed credentials %d times, want exactly once", successes)
	}
	if creds.verify("admin", "oldpassword") {
		t.Fatal("old password remained valid")
	}
}

func TestPasswordChangeUsesBoundedPasswordCheckLimiter(t *testing.T) {
	s := newTestServer(t)
	if err := s.creds.set("admin", "oldpassword"); err != nil {
		t.Fatal(err)
	}
	key := "password:" + "192.0.2.1"
	for range s.limiter.max {
		s.limiter.fail(key)
	}

	r := httptest.NewRequest(http.MethodPost, "/admin/api/auth/password", strings.NewReader(
		`{"current":"oldpassword","password":"newpassword"}`,
	))
	r.RemoteAddr = "192.0.2.1:12345"
	w := httptest.NewRecorder()
	s.handleAuthPassword(w, r)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("locked-out password change returned %d, want 429", w.Code)
	}
	if !s.creds.verify("admin", "oldpassword") {
		t.Fatal("rate-limited password change modified credentials")
	}
}
