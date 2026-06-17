// ==============================================================================
// MasterDnsVPN — zanoza-panel fork
// Per-domain keyring: lets one server process serve many delegated domains,
// each holding one or more encryption keys. Added for masterdns-zanoza-panel.
// ==============================================================================

// Package keyring resolves the per-domain set of decryption codecs for the
// MasterDnsVPN server. The DNS query domain is known (cleartext) before the
// tunnel labels are decrypted, so the server selects the right key(s) by
// domain. A domain with a single key decrypts directly (any cipher,
// including XOR). A domain holding 2+ keys must use AEAD ciphers so a wrong
// key fails authentication during trial decryption.
package keyring

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"masterdnsvpn-go/internal/security"

	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

const (
	maxKeyringBytes   = 32 << 20
	maxKeyringEntries = 4096
)

// Entry is one record in keyring.json written by the panel.
type Entry struct {
	Domain string `json:"domain"`
	Key    string `json:"key"`
	Method int    `json:"method"`
}

type keyringFile struct {
	Version    int     `json:"version"`
	Generation uint64  `json:"generation,omitempty"` // informational only; ACK is content-based
	Instances  []Entry `json:"instances"`
}

// ring holds the ordered codecs for a single domain. The first codec that
// authenticates a packet is promoted to the front so the hot key is tried
// first on subsequent packets.
type ring struct {
	mu     sync.Mutex
	codecs []*security.Codec
}

// Resolver maps normalized domain -> ring.
type Resolver struct {
	rings      map[string]*ring
	domains    []string
	digest     string // sha256 of the exact keyring.json content loaded
	generation uint64
}

// Digest returns the content digest of the loaded keyring. The acknowledgement
// is bound to content, not a reusable counter, so a stale marker can never be
// replayed or mistaken for a new configuration after a restart (R-03/F04).
func (r *Resolver) Digest() string {
	if r == nil {
		return ""
	}
	return r.digest
}

func (r *Resolver) Generation() uint64 {
	if r == nil {
		return 0
	}
	return r.generation
}

// DigestOf returns the canonical content digest for keyring bytes.
func DigestOf(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// WriteApplied atomically records the digest the server actually loaded, next
// to the keyring file, so the panel can confirm desired vs applied state (R-03).
func WriteApplied(keyringPath, digest string, generation uint64) error {
	raw, err := json.Marshal(struct {
		Digest     string `json:"digest"`
		Generation uint64 `json:"generation"`
	}{Digest: digest, Generation: generation})
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	target := keyringPath + ".applied"
	dir := filepath.Dir(target)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(target)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, target); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func normalizeDomain(domain string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
}

func validateDomain(domain string) error {
	if domain == "" || len(domain) > 253 || !strings.Contains(domain, ".") {
		return fmt.Errorf("invalid domain %q", domain)
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("invalid domain %q", domain)
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return fmt.Errorf("invalid domain %q", domain)
			}
		}
	}
	return nil
}

// Load reads keyring.json and builds the resolver.
func Load(path string) (*Resolver, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect keyring %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("keyring %s must be a regular non-symlink file", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read keyring %s: %w", path, err)
	}
	defer func() { _ = file.Close() }()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect opened keyring %s: %w", path, err)
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return nil, fmt.Errorf("keyring %s changed while opening", path)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxKeyringBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read keyring %s: %w", path, err)
	}
	if len(raw) > maxKeyringBytes {
		return nil, fmt.Errorf("keyring %s exceeds the %d-byte size limit", path, maxKeyringBytes)
	}
	currentInfo, err := os.Lstat(path)
	if err != nil || currentInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(openedInfo, currentInfo) {
		return nil, fmt.Errorf("keyring %s changed while reading", path)
	}
	if err := file.Chmod(0o600); err != nil {
		return nil, fmt.Errorf("secure keyring %s: %w", path, err)
	}
	currentInfo, err = os.Lstat(path)
	if err != nil || currentInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(openedInfo, currentInfo) {
		return nil, fmt.Errorf("keyring %s changed while securing", path)
	}
	var kf keyringFile
	if err := decodeStrictKeyring(raw, &kf); err != nil {
		return nil, fmt.Errorf("parse keyring %s: %w", path, err)
	}
	if kf.Version != 1 {
		return nil, fmt.Errorf("parse keyring %s: unsupported version %d", path, kf.Version)
	}
	r, err := FromEntries(kf.Instances)
	if err != nil {
		return nil, err
	}
	r.digest = DigestOf(raw)
	r.generation = kf.Generation
	return r, nil
}

func decodeStrictKeyring(raw []byte, dst any) error {
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
		return fmt.Errorf("keyring root must be a JSON object")
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

// isAEADMethod reports whether a cipher method authenticates (so multiple keys
// can be safely trial-decrypted on one domain). Mirrors the panel's rule (F06).
func isAEADMethod(method int) bool { return method >= 2 }

// FromEntries builds a resolver from already-parsed entries. The runtime loader
// does NOT trust panel validation: it canonicalizes domains, rejects duplicate
// keys within a (canonical) domain, and refuses to load any canonical domain
// that holds 2+ keys unless every method is AEAD — so legacy/canonical-collision
// configs fail closed instead of silently merging unsafe keys (F06).
func FromEntries(entries []Entry) (*Resolver, error) {
	if len(entries) > maxKeyringEntries {
		return nil, fmt.Errorf("keyring entry count %d exceeds limit %d", len(entries), maxKeyringEntries)
	}
	r := &Resolver{rings: map[string]*ring{}}
	seenDomain := map[string]bool{}
	keysPerDomain := map[string]map[string]struct{}{}
	methodsPerDomain := map[string][]int{}

	for _, e := range entries {
		domain := normalizeDomain(e.Domain)
		if err := validateDomain(domain); err != nil {
			return nil, err
		}
		key := strings.TrimSpace(e.Key)
		if key == "" {
			return nil, fmt.Errorf("empty key for domain %q", domain)
		}
		if keysPerDomain[domain] == nil {
			keysPerDomain[domain] = map[string]struct{}{}
		}
		if _, dup := keysPerDomain[domain][key]; dup {
			return nil, fmt.Errorf("duplicate key on domain %q", domain)
		}
		keysPerDomain[domain][key] = struct{}{}
		methodsPerDomain[domain] = append(methodsPerDomain[domain], e.Method)

		codec, err := security.NewCodec(e.Method, key)
		if err != nil {
			return nil, fmt.Errorf("codec for domain %q: %w", domain, err)
		}
		grp, ok := r.rings[domain]
		if !ok {
			grp = &ring{}
			r.rings[domain] = grp
			if !seenDomain[domain] {
				r.domains = append(r.domains, domain)
				seenDomain[domain] = true
			}
		}
		grp.codecs = append(grp.codecs, codec)
	}

	for domain, methods := range methodsPerDomain {
		if len(methods) < 2 {
			continue
		}
		for _, m := range methods {
			if !isAEADMethod(m) {
				return nil, fmt.Errorf("domain %q holds %d keys but method %d is not AEAD; refusing to load (canonical collision?)", domain, len(methods), m)
			}
		}
	}
	return r, nil
}

// Domains returns the distinct served domains (used to seed the matcher).
func (r *Resolver) Domains() []string {
	if r == nil {
		return nil
	}
	out := make([]string, len(r.domains))
	copy(out, r.domains)
	return out
}

// Empty reports whether the resolver carries no keys.
func (r *Resolver) Empty() bool {
	return r == nil || len(r.rings) == 0
}

// Parse decrypts+parses the tunnel labels using the codec(s) bound to the
// given domain. One key -> direct decrypt. Multiple keys -> trial decrypt
// with move-to-front promotion of the winning codec.
func (r *Resolver) Parse(domain, labels string) (VpnProto.Packet, error) {
	grp := r.rings[normalizeDomain(domain)]
	if grp == nil {
		return VpnProto.Packet{}, fmt.Errorf("no keys configured for domain %q", domain)
	}

	grp.mu.Lock()
	codecs := make([]*security.Codec, len(grp.codecs))
	copy(codecs, grp.codecs)
	grp.mu.Unlock()

	if len(codecs) == 1 {
		return VpnProto.ParseInflatedFromLabels(labels, codecs[0])
	}

	for i, codec := range codecs {
		packet, err := VpnProto.ParseInflatedFromLabels(labels, codec)
		if err == nil {
			if i != 0 {
				grp.promote(codec)
			}
			return packet, nil
		}
	}
	return VpnProto.Packet{}, fmt.Errorf("no key matched for domain %q", domain)
}

func (g *ring) promote(codec *security.Codec) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for i, c := range g.codecs {
		if c == codec {
			copy(g.codecs[1:i+1], g.codecs[0:i])
			g.codecs[0] = codec
			return
		}
	}
}
