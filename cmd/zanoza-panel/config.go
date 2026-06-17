package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	maxPanelConfigBytes = 32 << 20
	maxInstances        = 4096
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
	raw, err := readFileLimited(path, maxPanelConfigBytes)
	if err != nil {
		if os.IsNotExist(err) {
			cfg := defaultConfig()
			cfg.path = path
			if err := cfg.save(); err != nil {
				return nil, err
			}
			return cfg, nil
		}
		return nil, err
	}
	return parseConfig(path, raw)
}

func parseConfig(path string, raw []byte) (*Config, error) {
	cfg := defaultConfig()
	cfg.path = path
	if err := decodePanelConfig(raw, cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	cfg.path = path
	cfg.normalize()
	if err := cfg.validateRuntime(); err != nil {
		return nil, fmt.Errorf("invalid config %s: %w", path, err)
	}
	// Canonicalize + validate every persisted instance, so legacy/hand-edited
	// configs cannot smuggle canonical-collision domains past the runtime rules
	// (F06). Fail closed: an unsafe config refuses to start.
	if err := cfg.canonicalizeAndValidateInstances(); err != nil {
		return nil, fmt.Errorf("invalid config %s: %w", path, err)
	}
	return cfg, nil
}

// decodePanelConfig rejects unknown fields, duplicate object keys at any
// nesting level, non-object roots, and trailing JSON. Silently accepting a
// misspelled or shadowed security/runtime setting can otherwise start the panel
// with an unintended default.
func decodePanelConfig(raw []byte, cfg *Config) error {
	if err := decodeStrictJSONObject(raw, cfg); err != nil {
		return err
	}
	var envelope struct {
		Version *int `json:"version"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return err
	}
	if envelope.Version == nil || *envelope.Version != 1 {
		if envelope.Version == nil {
			return fmt.Errorf("config version is required")
		}
		return fmt.Errorf("unsupported config version %d", *envelope.Version)
	}
	return nil
}

func decodeStrictJSONObject(raw []byte, dst any) error {
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return fmt.Errorf("unexpected trailing JSON")
	}
	return nil
}

func rejectDuplicateJSONKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	first, err := dec.Token()
	if err != nil {
		return err
	}
	if first != json.Delim('{') {
		return fmt.Errorf("config root must be a JSON object")
	}
	if err := scanJSONObject(dec); err != nil {
		return err
	}
	if _, err := dec.Token(); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("unexpected trailing JSON")
		}
		return err
	}
	return nil
}

func scanJSONObject(dec *json.Decoder) error {
	seen := make(map[string]struct{})
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := token.(string)
		if !ok {
			return fmt.Errorf("object key is not a string")
		}
		foldedKey := strings.ToLower(key)
		if _, duplicate := seen[foldedKey]; duplicate {
			return fmt.Errorf("duplicate JSON key %q", key)
		}
		seen[foldedKey] = struct{}{}
		if err := scanJSONValue(dec); err != nil {
			return err
		}
	}
	return nil
}

func scanJSONValue(dec *json.Decoder) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		if err := scanJSONObject(dec); err != nil {
			return err
		}
		_, err = dec.Token()
		return err
	case '[':
		for dec.More() {
			if err := scanJSONValue(dec); err != nil {
				return err
			}
		}
		_, err = dec.Token()
		return err
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
}

// loadExistingConfig is used for runtime reloads. A missing configuration is
// an error here: recreating an empty first-run config during SIGHUP would
// discard the live instance set and stop the supervised DNS server.
func loadExistingConfig(path string) (*Config, error) {
	raw, err := readFileLimited(path, maxPanelConfigBytes)
	if err != nil {
		return nil, err
	}
	return parseConfig(path, raw)
}

// canonicalizeAndValidateInstances rewrites every instance domain to its
// canonical form and re-runs the multi-key/dup-key validation across the whole
// set (F06).
func (c *Config) canonicalizeAndValidateInstances() error {
	if len(c.Instances) > maxInstances {
		return fmt.Errorf("instance count %d exceeds limit %d", len(c.Instances), maxInstances)
	}
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
		c.Instances[i].ID = id

		d, err := canonicalDomain(c.Instances[i].Domain)
		if err != nil {
			return fmt.Errorf("instance %q: %w", id, err)
		}
		c.Instances[i].Domain = d
		// MasterDNS canonicalizes keyring keys with TrimSpace before deriving
		// crypto state. Persist and share that same canonical value so the panel,
		// server, and generated zanoza:// profile can never disagree.
		c.Instances[i].Key = strings.TrimSpace(c.Instances[i].Key)
	}
	for _, ins := range c.Instances {
		if err := validateInstance(c.Instances, ins, ins.ID); err != nil {
			return fmt.Errorf("instance %q (%s): %w", ins.ID, ins.Domain, err)
		}
	}
	return nil
}

func (c *Config) normalize() {
	if p, err := normalizePanelPath(c.PanelPath); err == nil {
		c.PanelPath = p
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

func (c *Config) validateRuntime() error {
	if c.Version != 1 {
		return fmt.Errorf("unsupported config version %d", c.Version)
	}
	p, err := normalizePanelPath(c.PanelPath)
	if err != nil {
		return fmt.Errorf("invalid panel_path: %w", err)
	}
	c.PanelPath = p
	if c.PanelPort < 1 || c.PanelPort > 65535 {
		return fmt.Errorf("panel_port must be in 1..65535")
	}
	if strings.TrimSpace(c.PanelAddr) == "" {
		return fmt.Errorf("panel_addr is required")
	}
	return nil
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
	err := c.validateRuntime()
	var raw []byte
	if err == nil {
		raw, err = json.MarshalIndent(c, "", "  ")
	}
	path := c.path
	c.mu.Unlock()
	if err != nil {
		return err
	}
	if len(raw) > maxPanelConfigBytes {
		return fmt.Errorf("serialized config exceeds the %d-byte size limit", maxPanelConfigBytes)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
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
	if err := work.validateRuntime(); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(work, "", "  ")
	if err != nil {
		return err
	}
	if len(raw) > maxPanelConfigBytes {
		return fmt.Errorf("serialized config exceeds the %d-byte size limit", maxPanelConfigBytes)
	}
	if err := os.MkdirAll(filepath.Dir(work.path), 0o700); err != nil {
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
