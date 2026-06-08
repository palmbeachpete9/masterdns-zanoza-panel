package keyring

import "testing"

// F06 — the keyring loader must not trust panel validation: canonical
// collisions with non-AEAD keys, and duplicate keys, fail closed.
func TestFromEntriesEnforcesMultiKeyAndDup(t *testing.T) {
	// Canonical collision ("v.example.com" vs "V.Example.com.") with non-AEAD
	// methods must be rejected.
	if _, err := FromEntries([]Entry{
		{Domain: "v.example.com", Key: "k1", Method: 1},
		{Domain: "V.Example.com.", Key: "k2", Method: 1},
	}); err == nil {
		t.Fatal("expected rejection of non-AEAD multi-key canonical collision")
	}

	// Duplicate key on one domain is rejected.
	if _, err := FromEntries([]Entry{
		{Domain: "v.example.com", Key: "same", Method: 2},
		{Domain: "v.example.com", Key: "same", Method: 2},
	}); err == nil {
		t.Fatal("expected duplicate-key rejection")
	}

	// Valid AEAD multi-key (across canonical-equivalent spellings) is accepted
	// and collapses to one domain.
	r, err := FromEntries([]Entry{
		{Domain: "v.example.com", Key: "k1", Method: 5},
		{Domain: "V.Example.com.", Key: "k2", Method: 5},
	})
	if err != nil {
		t.Fatalf("valid AEAD multi-key rejected: %v", err)
	}
	if len(r.Domains()) != 1 {
		t.Fatalf("canonical-equivalent domains did not collapse: %v", r.Domains())
	}
}
