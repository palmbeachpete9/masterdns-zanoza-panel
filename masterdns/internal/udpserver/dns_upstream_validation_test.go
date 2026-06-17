package udpserver

import (
	"encoding/binary"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"masterdnsvpn-go/internal/config"
)

func TestQueryOneUpstreamRejectsSameIDDifferentQuestion(t *testing.T) {
	upstream, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = upstream.Close() }()
	go func() {
		buf := make([]byte, 512)
		n, peer, readErr := upstream.ReadFromUDP(buf)
		if readErr != nil || n < 2 {
			return
		}
		response := testDNSAnswer(binary.BigEndian.Uint16(buf[:2]), "evil.example")
		_, _ = upstream.WriteToUDP(response, peer)
	}()
	s := New(config.ServerConfig{}, nil, nil)
	if response, err := s.queryOneUpstream(upstream.LocalAddr().String(), testDNSQuery(0x4242, "wanted.example"), time.Second); err == nil || len(response) != 0 {
		t.Fatalf("accepted unrelated response: err=%v bytes=%d", err, len(response))
	}
}

func TestResolveDNSUpstreamBoundsConcurrentHedges(t *testing.T) {
	upstream, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = upstream.Close() }()

	var received atomic.Int32
	go func() {
		buf := make([]byte, 512)
		for {
			if _, _, readErr := upstream.ReadFromUDP(buf); readErr != nil {
				return
			}
			received.Add(1)
		}
	}()

	servers := make([]string, 16)
	for i := range servers {
		servers[i] = upstream.LocalAddr().String()
	}
	s := New(config.ServerConfig{
		DNSUpstreamServers:     servers,
		DNSUpstreamTimeoutSecs: 0.45,
	}, nil, nil)
	if response, err := s.resolveDNSUpstream(testDNSQuery(0x4242, "wanted.example")); err == nil || len(response) != 0 {
		t.Fatalf("black-hole upstreams unexpectedly resolved: err=%v bytes=%d", err, len(response))
	}
	if got := received.Load(); got == 0 || got > maxConcurrentDNSUpstreamQueries {
		t.Fatalf("launched %d concurrent black-hole queries, want 1..%d", got, maxConcurrentDNSUpstreamQueries)
	}
}

func TestResolveDNSUpstreamStillReachesFallbackBeyondConcurrencyCap(t *testing.T) {
	bad, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = bad.Close() }()
	go func() {
		buf := make([]byte, 512)
		for {
			n, peer, readErr := bad.ReadFromUDP(buf)
			if readErr != nil {
				return
			}
			response := testDNSAnswer(binary.BigEndian.Uint16(buf[:n]), "evil.example")
			_, _ = bad.WriteToUDP(response, peer)
		}
	}()

	good, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = good.Close() }()
	go func() {
		buf := make([]byte, 512)
		n, peer, readErr := good.ReadFromUDP(buf)
		if readErr != nil {
			return
		}
		response := testDNSAnswer(binary.BigEndian.Uint16(buf[:n]), "wanted.example")
		_, _ = good.WriteToUDP(response, peer)
	}()

	servers := make([]string, maxConcurrentDNSUpstreamQueries+3)
	for i := range servers[:len(servers)-1] {
		servers[i] = bad.LocalAddr().String()
	}
	servers[len(servers)-1] = good.LocalAddr().String()
	s := New(config.ServerConfig{
		DNSUpstreamServers:     servers,
		DNSUpstreamTimeoutSecs: 2,
	}, nil, nil)
	if response, err := s.resolveDNSUpstream(testDNSQuery(0x4242, "wanted.example")); err != nil || len(response) == 0 {
		t.Fatalf("valid fallback beyond concurrency cap was not reached: err=%v bytes=%d", err, len(response))
	}
}

func testDNSQuery(id uint16, name string) []byte {
	out := make([]byte, 12)
	binary.BigEndian.PutUint16(out[0:2], id)
	binary.BigEndian.PutUint16(out[2:4], 0x0100)
	binary.BigEndian.PutUint16(out[4:6], 1)
	out = append(out, testDNSName(name)...)
	return append(out, 0, 1, 0, 1)
}

func testDNSAnswer(id uint16, name string) []byte {
	out := make([]byte, 12)
	binary.BigEndian.PutUint16(out[0:2], id)
	binary.BigEndian.PutUint16(out[2:4], 0x8180)
	binary.BigEndian.PutUint16(out[4:6], 1)
	binary.BigEndian.PutUint16(out[6:8], 1)
	out = append(out, testDNSName(name)...)
	out = append(out, 0, 1, 0, 1)
	return append(out, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 6, 6, 6, 6)
}

func testDNSName(name string) []byte {
	var out []byte
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			out = append(out, byte(i-start))
			out = append(out, name[start:i]...)
			start = i + 1
		}
	}
	return append(out, 0)
}
