package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
		Version:   1,
		Name:      "Zanoza Panel",
		PanelAddr: "0.0.0.0",
		PanelPort: 8443,
		PanelPath: "/admin",
		Instances: []Instance{},
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
	if c.PanelPath == "" {
		c.PanelPath = "/admin"
	}
	if c.PanelPath[0] != '/' {
		c.PanelPath = "/" + c.PanelPath
	}
	if c.Name == "" {
		c.Name = "Zanoza Panel"
	}
	if c.Instances == nil {
		c.Instances = []Instance{}
	}
}

func (c *Config) save() error {
	c.normalize()
	if err := os.MkdirAll(filepath.Dir(c.path), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.path)
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
