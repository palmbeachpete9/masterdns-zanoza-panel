package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Instance is one (domain, key, method) tuple handed to a user.
type Instance struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	Domain    string `json:"domain"`
	Key       string `json:"key"`
	Method    int    `json:"method"` // 0 None, 1 XOR, 2 ChaCha20, 3 AES-128, 4 AES-192, 5 AES-256
	CreatedAt string `json:"created_at"`
}

// Config is the persisted panel state.
type Config struct {
	Version   int        `json:"version"`
	Name      string     `json:"name"`
	PanelAddr string     `json:"panel_addr"`
	PanelPort int        `json:"panel_port"`
	PanelPath string     `json:"panel_path"`
	TLSCert   string     `json:"tls_cert"`
	TLSKey    string     `json:"tls_key"`
	Instances []Instance `json:"instances"`

	path       string
	mu         sync.Mutex
	commitMu   sync.Mutex // serializes the whole clone→persist→publish pipeline (F13)
	generation uint64     // bumped on every published change
}

func defaultConfig() *Config {
	return &Config{
		Version: 1,
		Name:    "Zanoza Panel",
		// Default to loopback: a config-less first start must never expose an
		// unauthenticated setup surface to the whole network (F03). The
		// installer writes an explicit bind address for production.
		PanelAddr: "127.0.0.1",
		PanelPort: 8443,
		PanelPath: "/admin",
		Instances: []Instance{},
	}
}

// ConfigMeta is an immutable snapshot of the live panel settings, taken under
// lock so HTTP handlers never read mutable Config fields concurrently with a
// settings update or a SIGHUP reload (F12).
type ConfigMeta struct {
	Name      string
	PanelAddr string
	PanelPort int
	PanelPath string
	TLSCert   string
	TLSKey    string
}

func (c *Config) Meta() ConfigMeta {
	c.mu.Lock()
	defer c.mu.Unlock()
	return ConfigMeta{
		Name:      c.Name,
		PanelAddr: c.PanelAddr,
		PanelPort: c.PanelPort,
		PanelPath: c.PanelPath,
		TLSCert:   c.TLSCert,
		TLSKey:    c.TLSKey,
	}
}

func loadConfig(path string) (*Config, error) {
	cfg := defaultConfig()
	cfg.path = path

	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			if err := cfg.save(); err != nil {
				return nil, err
			}
			return cfg, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(raw, cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	cfg.path = path
	cfg.normalize()
	// Canonicalize + validate every persisted instance, so legacy/hand-edited
	// configs cannot smuggle canonical-collision domains past the runtime rules
	// (F06). Fail closed: an unsafe config refuses to start.
	if err := cfg.canonicalizeAndValidateInstances(); err != nil {
		return nil, fmt.Errorf("invalid config %s: %w", path, err)
	}
	return cfg, nil
}

// canonicalizeAndValidateInstances rewrites every instance domain to its
// canonical form and re-runs the multi-key/dup-key validation across the whole
// set (F06).
func (c *Config) canonicalizeAndValidateInstances() error {
	// IDs must be non-empty and unique; otherwise validateInstance's "skip
	// siblings with my ID" rule lets two same-ID records hide each other and
	// bypass the multi-key/dup-key checks (R-05).
	seen := make(map[string]struct{}, len(c.Instances))
	for i := range c.Instances {
		id := strings.TrimSpace(c.Instances[i].ID)
		if id == "" {
			return fmt.Errorf("instance at index %d has an empty id", i)
		}
		if _, dup := seen[id]; dup {
			return fmt.Errorf("duplicate instance id %q", id)
		}
		seen[id] = struct{}{}

		d, err := canonicalDomain(c.Instances[i].Domain)
		if err != nil {
			return fmt.Errorf("instance %q: %w", id, err)
		}
		c.Instances[i].Domain = d
	}
	for _, ins := range c.Instances {
		if err := validateInstance(c.Instances, ins, ins.ID); err != nil {
			return fmt.Errorf("instance %q (%s): %w", ins.ID, ins.Domain, err)
		}
	}
	return nil
}

func (c *Config) normalize() {
	if c.Version == 0 {
		c.Version = 1
	}
	if p, err := normalizePanelPath(c.PanelPath); err == nil {
		c.PanelPath = p
	} else {
		c.PanelPath = "/admin"
	}
	if c.Name == "" {
		c.Name = "Zanoza Panel"
	}
	if c.PanelAddr == "" {
		c.PanelAddr = "127.0.0.1"
	}
	if c.Instances == nil {
		c.Instances = []Instance{}
	}
}

// normalizePanelPath returns the canonical admin path or an error. It enforces
// exactly one leading slash, forbids the bare root "/", forbids a trailing
// slash, and rejects whitespace/control/query/fragment characters and nested
// slashes — all of which previously produced router redirect loops such as
// "/" -> "//" or "/admin/" -> "/admin//" (F14).
func normalizePanelPath(raw string) (string, error) {
	p := strings.TrimSpace(raw)
	if p == "" {
		return "", fmt.Errorf("путь панели обязателен")
	}
	if p[0] != '/' {
		p = "/" + p
	}
	p = "/" + strings.Trim(p, "/") // collapse leading/trailing slashes
	if p == "/" {
		return "", fmt.Errorf("путь панели не может быть корнем «/»")
	}
	if strings.Contains(p[1:], "/") {
		return "", fmt.Errorf("путь панели не должен содержать вложенных слешей")
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f || r == ' ' || r == '?' || r == '#' || r == '%' {
			return "", fmt.Errorf("путь панели содержит недопустимый символ")
		}
	}
	return p, nil
}

func (c *Config) save() error {
	// Serialize normalize()+marshal against concurrent instance mutations so
	// json.Marshal never reads the slice while another request is writing it.
	// Callers never hold c.mu when calling save(), so this cannot deadlock.
	c.mu.Lock()
	c.normalize()
	raw, err := json.MarshalIndent(c, "", "  ")
	path := c.path
	c.mu.Unlock()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	// Atomic + durable write via a unique temp file, so concurrent saves no
	// longer race on one shared "config.json.tmp" path (F13).
	return writeFileAtomic(path, raw, 0o600)
}

// commit applies mutate to a deep clone of the live config, persists the clone
// atomically, and ONLY publishes it into the live object after the durable
// write succeeds (F13). A failed persistence therefore never diverges memory
// from disk, and commitMu serializes commits so a stale snapshot can't land
// after a newer one. The mutate callback must operate only on the work copy.
func (c *Config) commit(mutate func(work *Config) error) error {
	c.commitMu.Lock()
	defer c.commitMu.Unlock()

	c.mu.Lock()
	work := &Config{
		Version:   c.Version,
		Name:      c.Name,
		PanelAddr: c.PanelAddr,
		PanelPort: c.PanelPort,
		PanelPath: c.PanelPath,
		TLSCert:   c.TLSCert,
		TLSKey:    c.TLSKey,
		Instances: append([]Instance(nil), c.Instances...),
		path:      c.path,
	}
	c.mu.Unlock()

	if err := mutate(work); err != nil {
		return err
	}
	work.normalize()
	raw, err := json.MarshalIndent(work, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(work.path), 0o755); err != nil {
		return err
	}
	if err := writeFileAtomic(work.path, raw, 0o600); err != nil {
		return err // live state left untouched
	}

	c.mu.Lock()
	c.Version = work.Version
	c.Name = work.Name
	c.PanelAddr = work.PanelAddr
	c.PanelPort = work.PanelPort
	c.PanelPath = work.PanelPath
	c.TLSCert = work.TLSCert
	c.TLSKey = work.TLSKey
	c.Instances = work.Instances
	c.generation++
	c.mu.Unlock()
	return nil
}

// publishReload republishes externally-reloaded values in place (no disk write,
// so runtime-only env overrides aren't persisted) under the same commitMu that
// serializes commit(), so a SIGHUP reload can't interleave with an HTTP
// mutation and resurrect a stale snapshot (F13).
func (c *Config) publishReload(src *Config) {
	c.commitMu.Lock()
	defer c.commitMu.Unlock()
	c.mu.Lock()
	c.Version = src.Version
	c.Name = src.Name
	c.PanelAddr = src.PanelAddr
	c.PanelPort = src.PanelPort
	c.PanelPath = src.PanelPath
	c.TLSCert = src.TLSCert
	c.TLSKey = src.TLSKey
	c.Instances = append([]Instance(nil), src.Instances...)
	c.generation++
	c.mu.Unlock()
}

// Generation returns the current published generation number.
func (c *Config) Generation() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.generation
}

// snapshot returns a copy of the instance list under lock.
func (c *Config) snapshot() []Instance {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Instance, len(c.Instances))
	copy(out, c.Instances)
	return out
}

func newInstanceID() string {
	return fmt.Sprintf("ins_%d_%s", time.Now().UnixNano(), randomToken(4))
}
