package keyring

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"masterdnsvpn-go/internal/security"

	Enums "masterdnsvpn-go/internal/enums"

	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

const (
	keyA = "1111111111111111111111111111111111111111111111111111111111111111"
	keyB = "2222222222222222222222222222222222222222222222222222222222222222"
	keyC = "3333333333333333333333333333333333333333333333333333333333333333"
)

func encodeWith(t *testing.T, method int, key string) string {
	t.Helper()
	codec, err := security.NewCodec(method, key)
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	labels, err := VpnProto.BuildEncoded(VpnProto.BuildOptions{
		SessionID:     7,
		PacketType:    Enums.PACKET_SESSION_INIT,
		SessionCookie: 9,
	}, codec)
	if err != nil {
		t.Fatalf("BuildEncoded: %v", err)
	}
	return labels
}

func TestResolverDomainsAndEmpty(t *testing.T) {
	if !(&Resolver{}).Empty() {
		t.Fatal("zero resolver should be empty")
	}
	r, err := FromEntries([]Entry{
		{Domain: "V.A.com.", Key: keyA, Method: 1},
		{Domain: "v.b.com", Key: keyA, Method: 5},
		{Domain: "v.b.com", Key: keyB, Method: 5},
	})
	if err != nil {
		t.Fatalf("FromEntries: %v", err)
	}
	if r.Empty() {
		t.Fatal("resolver should not be empty")
	}
	domains := r.Domains()
	if len(domains) != 2 {
		t.Fatalf("domains = %v, want 2 distinct", domains)
	}
}

func TestSingleKeyDomainDirectParse(t *testing.T) {
	r, err := FromEntries([]Entry{{Domain: "v.a.com", Key: keyA, Method: 1}}) // XOR
	if err != nil {
		t.Fatalf("FromEntries: %v", err)
	}
	labels := encodeWith(t, 1, keyA)
	pkt, err := r.Parse("v.a.com", labels)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if pkt.PacketType != Enums.PACKET_SESSION_INIT || pkt.SessionID != 7 {
		t.Errorf("unexpected packet: type=%d session=%d", pkt.PacketType, pkt.SessionID)
	}
}

func TestMultiKeyDomainTrialSelectsCorrectKey(t *testing.T) {
	r, err := FromEntries([]Entry{
		{Domain: "v.b.com", Key: keyA, Method: 5}, // AES-256-GCM
		{Domain: "v.b.com", Key: keyB, Method: 5},
	})
	if err != nil {
		t.Fatalf("FromEntries: %v", err)
	}
	// Encrypted with the second key — trial must still find it.
	labels := encodeWith(t, 5, keyB)
	pkt, err := r.Parse("v.b.com", labels)
	if err != nil {
		t.Fatalf("Parse with in-ring key: %v", err)
	}
	if pkt.SessionID != 7 {
		t.Errorf("session = %d, want 7", pkt.SessionID)
	}

	// A key outside the ring must be rejected (AEAD auth fails on all).
	outside := encodeWith(t, 5, keyC)
	if _, err := r.Parse("v.b.com", outside); err == nil {
		t.Error("Parse should reject a key not present in the ring")
	}
}

func TestUnknownDomainRejected(t *testing.T) {
	r, _ := FromEntries([]Entry{{Domain: "v.a.com", Key: keyA, Method: 1}})
	if _, err := r.Parse("v.unknown.com", "labels"); err == nil {
		t.Error("Parse should reject an unconfigured domain")
	}
}

func TestWriteAppliedIsPrivateAndLeavesNoTempFile(t *testing.T) {
	keyringPath := filepath.Join(t.TempDir(), "keyring.json")
	if err := WriteApplied(keyringPath, "abc", 7); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(keyringPath + ".applied")
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("applied marker mode = %o, want 600", info.Mode().Perm())
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(keyringPath), ".keyring.json.applied.tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary applied markers left behind: %v", matches)
	}
}

func TestFromEntriesRejectsDomainsThatCannotAppearOnWire(t *testing.T) {
	for _, domain := range []string{
		"single-label",
		"bad..example.com",
		"-bad.example.com",
		"bad_.example.com",
		"bad.example.com..",
	} {
		t.Run(domain, func(t *testing.T) {
			if _, err := FromEntries([]Entry{{Domain: domain, Key: "k", Method: 5}}); err == nil {
				t.Fatalf("invalid domain %q was accepted", domain)
			}
		})
	}
}

func TestFromEntriesRejectsExcessiveEntryCount(t *testing.T) {
	entries := make([]Entry, maxKeyringEntries+1)
	if _, err := FromEntries(entries); err == nil {
		t.Fatal("excessive keyring entry count was accepted")
	}
}

func TestLoadRejectsOversizedKeyringBeforeDecode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keyring.json")
	if err := os.WriteFile(path, bytes.Repeat([]byte("x"), maxKeyringBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("oversized keyring was accepted")
	}
}

func TestLoadTightensExistingKeyringMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keyring.json")
	body := `{"version":1,"generation":7,"instances":[{"domain":"v.example.com","key":"` + keyA + `","method":5}]}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("keyring mode = %o, want 600", got)
	}
}

func TestLoadRejectsAmbiguousOrUnsupportedKeyringJSON(t *testing.T) {
	for name, body := range map[string]string{
		"duplicate root key":             `{"version":1,"version":1,"generation":1,"instances":[]}`,
		"case-folded duplicate root key": `{"version":1,"Version":1,"generation":1,"instances":[]}`,
		"duplicate entry key":            `{"version":1,"generation":1,"instances":[{"domain":"v.example.com","key":"a","key":"b","method":5}]}`,
		"unknown field":                  `{"version":1,"generation":1,"instances":[],"typo":true}`,
		"unsupported version":            `{"version":2,"generation":1,"instances":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "keyring.json")
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Fatalf("%s was accepted", name)
			}
		})
	}
}
