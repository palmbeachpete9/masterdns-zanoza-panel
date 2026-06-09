package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// keyringEntry is one record in keyring.json consumed by the forked
// MasterDnsVPN server.
type keyringEntry struct {
	Domain string `json:"domain"`
	Key    string `json:"key"`
	Method int    `json:"method"`
}

type keyringFile struct {
	Version   int            `json:"version"`
	Instances []keyringEntry `json:"instances"`
}

// RuntimeState is reported to the UI.
type RuntimeState struct {
	Status      string `json:"status"`
	Running     bool   `json:"running"`
	PID         int    `json:"pid,omitempty"`
	MemoryBytes int64  `json:"memory_bytes,omitempty"`
	StartedAt   string `json:"started_at,omitempty"`
	ExitedAt    string `json:"exited_at,omitempty"`
	ExitError   string `json:"exit_error,omitempty"`
	// Content-bound apply tracking (R-03): DesiredKeyring is the digest of the
	// keyring the panel last wrote; AppliedKeyring is the digest the running
	// server acknowledged loading. ApplyPending is true when the running server
	// has not (yet) acknowledged the exact desired keyring.
	DesiredKeyring string `json:"desired_keyring,omitempty"`
	AppliedKeyring string `json:"applied_keyring,omitempty"`
	ApplyPending   bool   `json:"apply_pending"`
	ApplyError     string `json:"apply_error,omitempty"`
}

// serverManager supervises the single MasterDnsVPN server process and keeps
// keyring.json in sync with the panel instances.
type serverManager struct {
	mu          sync.Mutex
	applyMu     sync.Mutex // serializes the full apply/restart pipeline (F04)
	binary      string
	runtimeDir  string
	keyringPath string
	configPath  string

	cmd          *exec.Cmd
	pid          int
	done         chan struct{} // closed by reap when cmd exits
	startedAt    time.Time
	exitedAt     time.Time
	exitErr      string
	lastApplyErr string

	desiredUp     bool      // operator intent: should the server be running?
	restarts      int       // auto-restarts within the current crash window
	windowAt      time.Time // start of the current crash-loop window
	desiredDigest string    // sha256 of the keyring the panel last wrote (R-03)
	desiredAt     time.Time // when desiredDigest was published (apply timeout, V4-06)
}

const applyAckTimeout = 15 * time.Second

// recordApplyErr stores an apply-stage failure in runtime state and returns it,
// so the state endpoint can surface the actual error (V4-06).
func (m *serverManager) recordApplyErr(err error) error {
	m.mu.Lock()
	m.lastApplyErr = err.Error()
	m.mu.Unlock()
	return err
}

const (
	crashWindow    = 60 * time.Second
	maxRestarts    = 5
	restartBackoff = 2 * time.Second
)

func newServerManager(runtimeDir string) *serverManager {
	bin := envDefault(EnvMasterdnsBin, "/usr/local/bin/masterdns-server")
	return &serverManager{
		binary:      bin,
		runtimeDir:  runtimeDir,
		keyringPath: filepath.Join(runtimeDir, "keyring.json"),
		configPath:  filepath.Join(runtimeDir, "server_config.toml"),
	}
}

// writeKeyring renders keyring.json + a base server_config.toml from the
// current instances and records the content digest the panel desires (R-03).
func (m *serverManager) writeKeyring(instances []Instance) error {
	if err := os.MkdirAll(m.runtimeDir, 0o755); err != nil {
		return m.recordApplyErr(err)
	}
	kf := keyringFile{Version: 1}
	for _, ins := range instances {
		kf.Instances = append(kf.Instances, keyringEntry{
			Domain: ins.Domain,
			Key:    ins.Key,
			Method: ins.Method,
		})
	}
	raw, err := json.MarshalIndent(kf, "", "  ")
	if err != nil {
		return m.recordApplyErr(err)
	}
	// digest of the exact bytes we are about to write; the server writes the
	// same digest to keyring.json.applied after it loads them (R-03).
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	// Atomic write so the server (which may reload concurrently on SIGHUP)
	// never reads a half-written keyring.json (F04).
	if err := writeFileAtomic(m.keyringPath, raw, 0o600); err != nil {
		return m.recordApplyErr(err)
	}
	if err := m.ensureServerConfig(); err != nil {
		return m.recordApplyErr(err)
	}
	// Publish the desired digest ONLY after the whole durable write transaction
	// succeeds, so a failed write never advances the reported desired state
	// (V4-06).
	m.mu.Lock()
	m.desiredDigest = digest
	m.desiredAt = time.Now()
	m.lastApplyErr = ""
	m.mu.Unlock()
	return nil
}

// ensureServerConfig writes a server_config.toml that points the forked
// server at keyring.json. The server derives DOMAIN + per-domain codecs
// from the keyring, so the panel only manages keyring.json afterwards.
func (m *serverManager) ensureServerConfig() error {
	if _, err := os.Stat(m.configPath); err == nil {
		return nil // keep admin-tuned config
	}
	dnsHost := envDefault(EnvDNSHost, "0.0.0.0")
	dnsPort := "53"
	if v := os.Getenv(EnvDNSPort); v != "" {
		if port, err := strconv.Atoi(v); err == nil && port > 0 && port <= 65535 {
			dnsPort = strconv.Itoa(port)
		} else {
			log.Printf("invalid %s=%q, using default", EnvDNSPort, v)
		}
	}
	dnsUpstream := `["1.1.1.1:53", "1.0.0.1:53"]`
	if v := os.Getenv(EnvDNSUpstream); v != "" {
		v = strings.TrimSpace(v)
		var parsed []string
		if err := json.Unmarshal([]byte(v), &parsed); err == nil && len(parsed) > 0 {
			dnsUpstream = v
		} else {
			log.Printf("invalid %s=%q, using default", EnvDNSUpstream, v)
		}
	}
	keyringPath := strings.ReplaceAll(m.keyringPath, `\`, `\\`)
	keyringPath = strings.ReplaceAll(keyringPath, `"`, `\"`)
	dnsHost = strings.ReplaceAll(dnsHost, `\`, `\\`)
	dnsHost = strings.ReplaceAll(dnsHost, `"`, `\"`)
	tmpl := fmt.Sprintf(`# Generated by zanoza-panel. Per-domain keys live in keyring.json.
KEYRING_FILE = "%s"
UDP_HOST = "%s"
UDP_PORT = %s
DNS_UPSTREAM_SERVERS = %s
LOG_LEVEL = "INFO"
`, keyringPath, dnsHost, dnsPort, dnsUpstream)
	return writeFileAtomic(m.configPath, []byte(tmpl), 0o644)
}

// apply renders the keyring then reloads or (re)starts the server. The whole
// pipeline is serialized under applyMu so concurrent CRUD can never interleave
// renders/reloads, and signal/start failures are returned to the caller (F04).
func (m *serverManager) apply(instances []Instance) error {
	m.applyMu.Lock()
	defer m.applyMu.Unlock()

	if err := m.writeKeyring(instances); err != nil {
		return err
	}

	if len(instances) == 0 {
		// Nothing to serve; stop the process if it's up.
		m.stop()
		return nil
	}

	m.mu.Lock()
	running := m.cmd != nil && m.pid != 0
	pid := m.pid
	m.desiredUp = true
	m.mu.Unlock()

	if running {
		// Ask the server to reload keyring.json in place; surface a dead-PID
		// or permission failure instead of silently swallowing it.
		if err := syscall.Kill(pid, syscall.SIGHUP); err != nil {
			m.mu.Lock()
			m.lastApplyErr = "reload signal failed: " + err.Error()
			m.mu.Unlock()
			return fmt.Errorf("reload (SIGHUP pid %d) failed: %w", pid, err)
		}
		return nil
	}
	return m.start()
}

func (m *serverManager) start() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.startLocked()
}

// startLocked launches the server. Caller holds m.mu.
func (m *serverManager) startLocked() error {
	if m.cmd != nil && m.pid != 0 {
		return nil
	}
	if _, err := os.Stat(m.binary); err != nil {
		m.lastApplyErr = "server binary not found: " + m.binary
		return fmt.Errorf("%s", m.lastApplyErr)
	}
	cmd := exec.Command(m.binary, "-config", m.configPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		m.lastApplyErr = err.Error()
		return err
	}
	done := make(chan struct{})
	m.cmd = cmd
	m.pid = cmd.Process.Pid
	m.done = done
	m.startedAt = time.Now()
	m.exitErr = ""
	m.lastApplyErr = ""
	m.desiredUp = true
	go m.reap(cmd, done)
	return nil
}

// reap is the single owner of cmd.Wait() for one process generation. On an
// unexpected exit (operator still wants it up) it auto-restarts with bounded
// backoff and a crash-loop ceiling; a deliberate stop is not restarted (F09).
func (m *serverManager) reap(cmd *exec.Cmd, done chan struct{}) {
	err := cmd.Wait()

	m.mu.Lock()
	if m.cmd != cmd {
		// Superseded by a newer generation; do not clobber its state.
		m.mu.Unlock()
		close(done)
		return
	}
	m.cmd = nil
	m.pid = 0
	m.exitedAt = time.Now()
	if err != nil {
		m.exitErr = err.Error()
	}

	restart := false
	var backoff time.Duration
	var attempt int
	var crashLoopMsg string
	if m.desiredUp {
		now := time.Now()
		if now.Sub(m.windowAt) > crashWindow {
			m.windowAt = now
			m.restarts = 0
		}
		m.restarts++
		if m.restarts > maxRestarts {
			crashLoopMsg = fmt.Sprintf("masterdns crash loop: %d restarts within %s; supervisor stopped", m.restarts, crashWindow)
			m.lastApplyErr = crashLoopMsg
			m.desiredUp = false
		} else {
			restart = true
			attempt = m.restarts
			backoff = time.Duration(m.restarts) * restartBackoff
		}
	}
	m.mu.Unlock()

	// Process state is now fully cleared under the lock; only AFTER that do we
	// signal completion, so a concurrent stop()/restart() waiting on done can
	// never observe stale m.cmd/m.pid (F09).
	close(done)

	if crashLoopMsg != "" {
		log.Printf("masterdns: %s", crashLoopMsg)
	}
	if !restart {
		return
	}
	log.Printf("masterdns exited (%v); auto-restart in %s (attempt %d/%d)", err, backoff, attempt, maxRestarts)
	go func() {
		time.Sleep(backoff)
		m.mu.Lock()
		defer m.mu.Unlock()
		if !m.desiredUp || m.cmd != nil {
			return
		}
		if err := m.startLocked(); err != nil {
			log.Printf("masterdns auto-restart failed: %v", err)
		}
	}()
}

func (m *serverManager) stop() {
	m.mu.Lock()
	m.desiredUp = false
	cmd := m.cmd
	pid := m.pid
	done := m.done
	m.mu.Unlock()
	if cmd == nil || pid == 0 {
		return
	}
	_ = syscall.Kill(pid, syscall.SIGTERM)
	if done == nil {
		return
	}
	// Wait for reap (the sole cmd.Wait owner) to observe the exit. No second
	// Wait is ever issued, avoiding the previous double-Wait race (F09).
	select {
	case <-done:
	case <-time.After(8 * time.Second):
		_ = cmd.Process.Kill()
		<-done
	}
}

func (m *serverManager) restart(instances []Instance) error {
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	m.stop()
	if len(instances) == 0 {
		return nil
	}
	if err := m.writeKeyring(instances); err != nil {
		return err
	}
	return m.start()
}

func (m *serverManager) state() RuntimeState {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := RuntimeState{}
	if m.cmd != nil && m.pid != 0 {
		st.Running = true
		st.Status = "running"
		st.PID = m.pid
		st.StartedAt = m.startedAt.UTC().Format(time.RFC3339)
		st.MemoryBytes = processMemoryBytes(m.pid)
	} else {
		st.Status = "stopped"
		if m.lastApplyErr != "" {
			st.ExitError = m.lastApplyErr
		} else if m.exitErr != "" {
			st.ExitError = m.exitErr
		}
		if !m.exitedAt.IsZero() {
			st.ExitedAt = m.exitedAt.UTC().Format(time.RFC3339)
		}
	}
	// Content-bound desired vs applied (R-03): the panel knows the digest it
	// wrote; the running server records the digest it actually loaded. A missing
	// or mismatched marker is treated as NOT applied (never as a false success).
	applied := readAppliedDigest(m.keyringPath)
	st.DesiredKeyring = m.desiredDigest
	st.AppliedKeyring = applied
	acknowledged := m.desiredDigest != "" && applied == m.desiredDigest
	st.ApplyPending = st.Running && !acknowledged

	switch {
	case acknowledged:
		// The running server confirmed the exact desired keyring: the apply
		// succeeded, so a stale earlier error is reconciled away (V4-06).
		m.lastApplyErr = ""
	case st.ApplyPending && !m.desiredAt.IsZero() && time.Since(m.desiredAt) > applyAckTimeout:
		// Bounded acknowledgement timeout: pending becomes degraded with a
		// concrete error rather than hanging "pending" forever (V4-06).
		if m.lastApplyErr == "" {
			m.lastApplyErr = "masterdns did not acknowledge the desired keyring within timeout"
		}
		st.Status = "degraded"
	}
	if m.lastApplyErr != "" {
		st.ApplyError = m.lastApplyErr
	}
	return st
}

// readAppliedDigest reads the content digest the MasterDNS server acknowledged
// loading (written next to keyring.json). Returns "" (unacknowledged) if the
// marker is absent or unreadable — never a value that could look applied (R-03).
func readAppliedDigest(keyringPath string) string {
	raw, err := os.ReadFile(keyringPath + ".applied")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

// processMemoryBytes reads RSS from /proc on Linux; best-effort elsewhere.
func processMemoryBytes(pid int) int64 {
	if runtime.GOOS != "linux" || pid <= 0 {
		return 0
	}
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/statm", pid))
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(raw))
	if len(fields) < 2 {
		return 0
	}
	rssPages, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return 0
	}
	return rssPages * int64(os.Getpagesize())
}
