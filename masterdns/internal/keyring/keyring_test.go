package keyring

import (
	"testing"

	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/security"
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
