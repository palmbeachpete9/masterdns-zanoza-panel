package config

import "testing"

// R-10 — flag binders must return empty overrides on a nil receiver, not panic.
func TestFlagBindersNilReceiver(t *testing.T) {
	if got := (*ClientConfigFlagBinder)(nil).Overrides(); got.Values == nil || len(got.Values) != 0 {
		t.Fatalf("client nil binder: %#v", got)
	}
	if got := (*ServerConfigFlagBinder)(nil).Overrides(); got.Values == nil || len(got.Values) != 0 {
		t.Fatalf("server nil binder: %#v", got)
	}
}
