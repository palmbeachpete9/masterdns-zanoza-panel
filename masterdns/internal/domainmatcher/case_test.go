package domainmatcher

import (
	"testing"

	Enums "masterdnsvpn-go/internal/enums"
)

// F23 — DNS names are case-insensitive; every case variant of an allowed base
// domain must match, while the original-case tunnel labels are preserved.
func TestMatcherCaseInsensitiveBaseDomain(t *testing.T) {
	m := New([]string{"v.example.com"}, 3)

	for _, name := range []string{
		"AbCdEf.v.example.com",
		"AbCdEf.V.EXAMPLE.COM",
		"abcdef.v.Example.Com.",
	} {
		d := m.Match(litePacketWithQuestion(name, Enums.DNS_RECORD_TYPE_TXT))
		if d.Action != ActionProcess {
			t.Errorf("%q: action=%v reason=%s; want ActionProcess", name, d.Action, d.Reason)
			continue
		}
		// Tunnel data labels keep their original case for decoding.
		if d.Labels != "AbCdEf" && d.Labels != "abcdef" {
			t.Errorf("%q: labels=%q; want case preserved", name, d.Labels)
		}
	}

	// Unauthorized domains stay unauthorized after canonicalization.
	if d := m.Match(litePacketWithQuestion("AbC.evil.com", Enums.DNS_RECORD_TYPE_TXT)); d.Action == ActionProcess {
		t.Error("unauthorized domain matched")
	}
}
