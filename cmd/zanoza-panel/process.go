package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math"
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
	Version    int            `json:"version"`
	Generation uint64         `json:"generation"`
	Instances  []keyringEntry `json:"instances"`
}

type appliedMarker struct {
	Digest     string `json:"digest"`
	Generation uint64 `json:"generation"`
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
	desiredGen    uint64    // monotonically identifies the current apply attempt
	desiredAt     time.Time // when desiredDigest was published (apply timeout, V4-06)
	restartDelay  time.Duration
}

const applyAckTimeout = 15 * time.Second

const (
	maxAppliedMarkerBytes = 4 << 10
	maxKeyringFileBytes   = 32 << 20
)

// recordApplyErr stores an apply-stage failure in runtime state and returns it,
// so the state endpoint can surface the actual error (V4-06).
func (m *serverManager) recordApplyErr(err error) error {
	m.mu.Lock()
	m.lastApplyErr = err.Error()
	m.mu.Unlock()
	return err
}

const (
	crashWindow         = 60 * time.Second
	maxRestarts         = 5
	defaultRestartDelay = 2 * time.Second
	stopGraceTimeout    = 8 * time.Second
	stopKillTimeout     = 2 * time.Second
)

func newServerManager(runtimeDir string) *serverManager {
	bin := envDefault(EnvMasterdnsBin, "/usr/local/bin/masterdns-server")
	m := &serverManager{
		binary:       bin,
		runtimeDir:   runtimeDir,
		keyringPath:  filepath.Join(runtimeDir, "keyring.json"),
		configPath:   filepath.Join(runtimeDir, "server_config.toml"),
		restartDelay: defaultRestartDelay,
	}
	m.desiredGen = readGenerationWatermark(m.keyringPath)
	return m
}

// writeKeyring renders keyring.json + a base server_config.toml from the
// current instances and records the content digest the panel desires (R-03).
func (m *serverManager) writeKeyring(instances []Instance) error {
	if err := os.MkdirAll(m.runtimeDir, 0o700); err != nil {
		return m.recordApplyErr(err)
	}
	m.mu.Lock()
	if m.desiredGen == math.MaxUint64 {
		m.mu.Unlock()
		return m.recordApplyErr(fmt.Errorf("keyring generation exhausted"))
	}
	generation := m.desiredGen + 1
	m.mu.Unlock()
	kf := keyringFile{Version: 1, Generation: generation}
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
	if len(raw) > maxKeyringFileBytes {
		return m.recordApplyErr(fmt.Errorf("serialized keyring exceeds the %d-byte size limit", maxKeyringFileBytes))
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
	m.desiredGen = generation
	m.desiredAt = time.Now()
	m.lastApplyErr = ""
	m.mu.Unlock()
	return nil
}

// ensureServerConfig writes a server_config.toml that points the forked
// server at keyring.json. The server derives DOMAIN + per-domain codecs
// from the keyring, so the panel only manages keyring.json afterwards.
func (m *serverManager) ensureServerConfig() error {
	info, err := os.Lstat(m.configPath)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("%s must be a regular non-symlink file", m.configPath)
		}
		return nil // keep admin-tuned config
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("inspect server config %s: %w", m.configPath, err)
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
		return m.stop()
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
	cmd.Env = environmentWithout(os.Environ(), EnvPassword)
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

func environmentWithout(environment []string, keys ...string) []string {
	blocked := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		blocked[key] = struct{}{}
	}
	filtered := make([]string, 0, len(environment))
	for _, item := range environment {
		key, _, _ := strings.Cut(item, "=")
		if _, remove := blocked[key]; !remove {
			filtered = append(filtered, item)
		}
	}
	return filtered
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
			backoff = m.restartBackoffLocked(m.restarts)
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
	m.scheduleAutoRestart(err, backoff)
}

func (m *serverManager) restartBackoffLocked(attempt int) time.Duration {
	delay := m.restartDelay
	if delay <= 0 {
		delay = defaultRestartDelay
	}
	return time.Duration(attempt) * delay
}

// scheduleAutoRestart keeps retrying launch failures within the same bounded
// crash-loop budget. A failed exec previously had no process to reap, so one
// transient launch failure silently ended supervision while desiredUp stayed
// true forever.
func (m *serverManager) scheduleAutoRestart(exitErr error, backoff time.Duration) {
	go func() {
		for {
			time.Sleep(backoff)

			m.mu.Lock()
			if !m.desiredUp || m.cmd != nil {
				m.mu.Unlock()
				return
			}
			err := m.startLocked()
			if err == nil {
				m.mu.Unlock()
				return
			}

			now := time.Now()
			if now.Sub(m.windowAt) > crashWindow {
				m.windowAt = now
				m.restarts = 0
			}
			m.restarts++
			attempt := m.restarts
			if attempt > maxRestarts {
				msg := fmt.Sprintf("masterdns restart launch loop: %d attempts within %s; supervisor stopped after %v", attempt, crashWindow, err)
				m.lastApplyErr = msg
				m.desiredUp = false
				m.mu.Unlock()
				log.Printf("masterdns: %s", msg)
				return
			}
			backoff = m.restartBackoffLocked(attempt)
			m.mu.Unlock()

			log.Printf("masterdns auto-restart launch failed after exit (%v): %v; retry in %s (attempt %d/%d)", exitErr, err, backoff, attempt, maxRestarts)
		}
	}()
}

func (m *serverManager) stop() error {
	return m.stopWithTimeout(stopGraceTimeout, stopKillTimeout)
}

func (m *serverManager) stopWithTimeout(graceTimeout, killTimeout time.Duration) error {
	m.mu.Lock()
	m.desiredUp = false
	cmd := m.cmd
	pid := m.pid
	done := m.done
	m.mu.Unlock()
	if cmd == nil || pid == 0 {
		return nil
	}
	if done == nil {
		err := fmt.Errorf("masterdns stop cannot wait for pid %d: missing process completion channel", pid)
		return m.recordApplyErr(err)
	}
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		select {
		case <-done:
			return nil
		default:
		}
		stopErr := fmt.Errorf("masterdns stop failed to signal pid %d: %w", pid, err)
		return m.recordApplyErr(stopErr)
	}
	// Wait for reap (the sole cmd.Wait owner) to observe the exit. No second
	// Wait is ever issued, avoiding the previous double-Wait race (F09).
	select {
	case <-done:
		return nil
	case <-time.After(graceTimeout):
	}

	var killErr error
	if cmd.Process == nil {
		killErr = fmt.Errorf("missing process handle")
	} else {
		killErr = cmd.Process.Kill()
	}

	select {
	case <-done:
		return nil
	case <-time.After(killTimeout):
	}

	if killErr != nil {
		return m.recordApplyErr(fmt.Errorf("masterdns stop timed out after SIGTERM and failed to kill pid %d: %w", pid, killErr))
	}
	return m.recordApplyErr(fmt.Errorf("masterdns stop timed out waiting for pid %d after SIGTERM and kill", pid))
}

func (m *serverManager) restart(instances []Instance) error {
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	if err := m.stop(); err != nil {
		return err
	}
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
	applied := readAppliedMarker(m.keyringPath)
	st.DesiredKeyring = m.desiredDigest
	st.AppliedKeyring = applied.Digest
	acknowledged := st.Running && m.desiredDigest != "" &&
		applied.Digest == m.desiredDigest && applied.Generation == m.desiredGen
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
func readAppliedMarker(keyringPath string) appliedMarker {
	raw, err := readFileLimited(keyringPath+".applied", maxAppliedMarkerBytes)
	if err != nil {
		return appliedMarker{}
	}
	var marker appliedMarker
	if decodeStrictJSONObject(raw, &marker) != nil || marker.Digest == "" || marker.Generation == 0 {
		return appliedMarker{}
	}
	return marker
}

// readGenerationWatermark prevents generation reuse after a panel restart.
// Reusing an old generation with identical instance content would recreate the
// same digest and let a stale applied marker look current before MasterDNS had
// actually reloaded the new write.
func readGenerationWatermark(keyringPath string) uint64 {
	var watermark uint64
	var keyringDigest string
	if raw, err := readFileLimited(keyringPath, maxKeyringFileBytes); err == nil {
		var persisted keyringFile
		if decodeStrictJSONObject(raw, &persisted) == nil && persisted.Version == 1 {
			watermark = persisted.Generation
			sum := sha256.Sum256(raw)
			keyringDigest = hex.EncodeToString(sum[:])
		}
	}
	// Trust a newer service-written marker only when it acknowledges the exact
	// persisted keyring. Otherwise stale/corrupt state (including MaxUint64)
	// could permanently prevent every future apply.
	if marker := readAppliedMarker(keyringPath); marker.Digest == keyringDigest && marker.Generation > watermark {
		watermark = marker.Generation
	}
	return watermark
}

func readAppliedDigest(keyringPath string) string {
	return readAppliedMarker(keyringPath).Digest
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
