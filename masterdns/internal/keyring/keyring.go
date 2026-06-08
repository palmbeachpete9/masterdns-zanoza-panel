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
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"masterdnsvpn-go/internal/security"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

// Entry is one record in keyring.json written by the panel.
type Entry struct {
	Domain string `json:"domain"`
	Key    string `json:"key"`
	Method int    `json:"method"`
}

type keyringFile struct {
	Version    int     `json:"version"`
	Generation uint64  `json:"generation,omitempty"`
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
	generation uint64
}

// Generation returns the panel-assigned generation of this keyring (F04).
func (r *Resolver) Generation() uint64 {
	if r == nil {
		return 0
	}
	return r.generation
}

// WriteApplied records the generation the server has actually loaded, next to
// the keyring file, so the panel can confirm desired vs applied state (F04).
func WriteApplied(keyringPath string, generation uint64) error {
	return os.WriteFile(keyringPath+".applied", []byte(fmt.Sprintf("%d\n", generation)), 0o600)
}

func normalizeDomain(domain string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
}

// Load reads keyring.json and builds the resolver.
func Load(path string) (*Resolver, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read keyring %s: %w", path, err)
	}
	var kf keyringFile
	if err := json.Unmarshal(raw, &kf); err != nil {
		return nil, fmt.Errorf("parse keyring %s: %w", path, err)
	}
	r, err := FromEntries(kf.Instances)
	if err != nil {
		return nil, err
	}
	r.generation = kf.Generation
	return r, nil
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
	r := &Resolver{rings: map[string]*ring{}}
	seenDomain := map[string]bool{}
	keysPerDomain := map[string]map[string]struct{}{}
	methodsPerDomain := map[string][]int{}

	for _, e := range entries {
		domain := normalizeDomain(e.Domain)
		if domain == "" {
			return nil, fmt.Errorf("empty domain in keyring")
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
