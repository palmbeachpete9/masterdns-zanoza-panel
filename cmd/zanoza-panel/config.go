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

	path string
	mu   sync.Mutex
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
	return cfg, nil
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
