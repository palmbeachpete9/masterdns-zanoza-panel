package udpserver

import (
	"context"
	"net"
	"testing"
)

// F19 — the SOCKS private-network filter must not be bypassed by hostnames
// (including "localhost.") or by DNS answers that resolve/rebind to private IPs.
func TestSOCKSAuthorizeBlocksHostnameRebinding(t *testing.T) {
	// Static pre-check catches localhost variants and literal private IPs.
	for _, h := range []string{"localhost", "localhost.", "LOCALHOST.", "127.0.0.1", "10.0.0.5", "::1", "192.168.1.1"} {
		if err := validateSOCKSTargetHost(h); err == nil {
			t.Errorf("validateSOCKSTargetHost(%q) allowed; want blocked", h)
		}
	}
	if err := validateSOCKSTargetHost("example.com"); err != nil {
		t.Errorf("validateSOCKSTargetHost(public host) = %v; want nil", err)
	}

	// A hostname that resolves to a loopback/private address must be blocked
	// (DNS rebinding), and the dialer must pin the validated public IP.
	priv := &Server{resolveIPAddrFn: func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	}}
	if _, err := priv.authorizeSOCKSTarget(context.Background(), "evil.example.com"); err == nil {
		t.Error("hostname resolving to loopback was allowed")
	}

	pub := &Server{resolveIPAddrFn: func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
	}}
	ip, err := pub.authorizeSOCKSTarget(context.Background(), "good.example.com")
	if err != nil || ip != "93.184.216.34" {
		t.Fatalf("authorize public = %q,%v; want pinned 93.184.216.34", ip, err)
	}

	// localhost. as a hostname is blocked before any resolution.
	if _, err := pub.authorizeSOCKSTarget(context.Background(), "localhost."); err == nil {
		t.Error(`"localhost." was allowed`)
	}

	// If ANY resolved address is private, the whole target is rejected.
	mixed := &Server{resolveIPAddrFn: func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}, {IP: net.ParseIP("169.254.169.254")}}, nil
	}}
	if _, err := mixed.authorizeSOCKSTarget(context.Background(), "rebind.example.com"); err == nil {
		t.Error("target with a private resolved address (cloud metadata) was allowed")
	}
}
