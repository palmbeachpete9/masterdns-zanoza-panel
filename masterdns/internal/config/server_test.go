// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package config

import (
	"encoding/base64"
	"flag"
	"math"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestServerConfigRejectsInvalidUDPHostInsteadOfBindingWildcard(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server_config.toml")
	if err := os.WriteFile(path, []byte(`
UDP_HOST = "not-an-ip"
UDP_PORT = 53
DOMAIN = ["v.example.com"]
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadServerConfig(path); err == nil {
		t.Fatal("invalid UDP_HOST was accepted; net.ParseIP(nil) would bind wildcard")
	}
}

func TestServerConfigAddressFormatsIPv6(t *testing.T) {
	cfg := ServerConfig{UDPHost: "::1", UDPPort: 53}
	if got, want := cfg.Address(), net.JoinHostPort("::1", "53"); got != want {
		t.Fatalf("Address() = %q, want %q", got, want)
	}
}

func TestServerConfigRejectsOversizedPacketBuffer(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server_config.toml")
	if err := os.WriteFile(path, []byte(`
UDP_PORT = 53
MAX_PACKET_SIZE = 1073741824
DOMAIN = ["v.example.com"]
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadServerConfig(path); err == nil {
		t.Fatal("oversized packet buffer was accepted")
	}
}

func TestServerConfigRejectsInvalidEncryptionMethodInsteadOfDowngrading(t *testing.T) {
	cfg := defaultServerConfig()
	cfg.DataEncryptionMethod = 99
	if _, err := finalizeServerConfig(cfg); err == nil {
		t.Fatal("invalid encryption method was silently downgraded")
	}
}

func TestServerConfigRejectsUnknownKeys(t *testing.T) {
	t.Run("toml", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "server.toml")
		if err := os.WriteFile(path, []byte(`
DOMAIN = ["v.example.com"]
DATA_ENCRYPTION_METHDO = 5
`), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadServerConfig(path); err == nil {
			t.Fatal("unknown TOML key was silently ignored")
		}
	})

	t.Run("json", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte(`{
			"DOMAIN": ["v.example.com"],
			"DATA_ENCRYPTION_METHDO": 5
		}`))
		if _, err := LoadServerConfigFromJSONBase64(encoded); err == nil {
			t.Fatal("unknown JSON key was silently ignored")
		}
	})

	t.Run("duplicate JSON key", func(t *testing.T) {
		raw := []byte(`{"UDP_PORT":53,"UDP_PORT":5353}`)
		encoded := base64.StdEncoding.EncodeToString(raw)
		if _, err := LoadServerConfigFromJSONBase64(encoded); err == nil {
			t.Fatal("duplicate JSON config key was accepted")
		}
	})

	t.Run("non-object JSON", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte(`null`))
		if _, err := LoadServerConfigFromJSONBase64(encoded); err == nil {
			t.Fatal("non-object JSON config was accepted")
		}
	})
}

func TestServerConfigRejectsOversizedConfigFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server_config.toml")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxConfigBytes + 1); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadServerConfig(path); err == nil {
		t.Fatal("oversized config file was accepted")
	}
}

func TestServerConfigNormalizesNonFiniteAndExtremeDurations(t *testing.T) {
	cfg := defaultServerConfig()
	cfg.DropLogIntervalSecs = math.NaN()
	cfg.SessionTimeoutSecs = math.Inf(1)
	cfg.DNSUpstreamTimeoutSecs = 1e300
	cfg.DNSCacheTTLSeconds = 1e300

	final, err := finalizeServerConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]time.Duration{
		"drop log interval":     final.DropLogInterval(),
		"session timeout":       final.SessionTimeout(),
		"dns upstream timeout":  final.DNSUpstreamTimeout(),
		"dns cache ttl seconds": time.Duration(final.DNSCacheTTLSeconds * float64(time.Second)),
	} {
		if value <= 0 {
			t.Fatalf("%s overflowed to non-positive duration: %s", name, value)
		}
	}
}

func TestServerConfigRejectsExcessiveFanoutLists(t *testing.T) {
	for name, mutate := range map[string]func(*ServerConfig){
		"upstreams": func(cfg *ServerConfig) {
			cfg.DNSUpstreamServers = make([]string, maxConfiguredDNSUpstreams+1)
		},
		"domains": func(cfg *ServerConfig) {
			cfg.Domain = make([]string, maxConfiguredDomains+1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := defaultServerConfig()
			mutate(&cfg)
			if _, err := finalizeServerConfig(cfg); err == nil {
				t.Fatal("excessive fanout list was accepted")
			}
		})
	}
}

func TestServerConfigClampsDirectResourceSizingFields(t *testing.T) {
	cfg := defaultServerConfig()
	cfg.UDPReaders = int(^uint(0) >> 1)
	cfg.SocketBufferSize = int(^uint(0) >> 1)
	cfg.MaxConcurrentRequests = int(^uint(0) >> 1)
	cfg.DNSRequestWorkers = int(^uint(0) >> 1)
	cfg.DNSCacheMaxRecords = int(^uint(0) >> 1)

	final, err := finalizeServerConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if final.UDPReaders > 32 || final.SocketBufferSize > 256*1024*1024 ||
		final.MaxConcurrentRequests > 131072 || final.DNSRequestWorkers > 256 ||
		final.DNSCacheMaxRecords > 500000 {
		t.Fatalf("direct resource fields were not clamped: %+v", final)
	}
}

func TestServerConfigRejectsInvalidDomainsBeforeBuildingMatcher(t *testing.T) {
	for _, domain := range []string{"com", "bad..example.com", "-bad.example.com", "bad_.example.com"} {
		t.Run(domain, func(t *testing.T) {
			cfg := defaultServerConfig()
			cfg.Domain = []string{domain}
			if _, err := finalizeServerConfig(cfg); err == nil {
				t.Fatalf("invalid domain %q was accepted", domain)
			}
		})
	}

	cfg := defaultServerConfig()
	cfg.Domain = []string{" V.Example.COM. ", "v.example.com"}
	final, err := finalizeServerConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(final.Domain) != 1 || final.Domain[0] != "v.example.com" {
		t.Fatalf("domains not canonicalized/deduplicated: %v", final.Domain)
	}
}

func TestServerConfigRejectsInvalidDNSUpstreamsAtStartup(t *testing.T) {
	for _, upstream := range []string{"", ":53", "1.1.1.1:", "1.1.1.1:99999", "[::1]", "not:an:ip", "bad host", "-bad.example:53"} {
		t.Run(upstream, func(t *testing.T) {
			cfg := defaultServerConfig()
			cfg.DNSUpstreamServers = []string{upstream}
			if _, err := finalizeServerConfig(cfg); err == nil {
				t.Fatalf("invalid upstream %q was accepted", upstream)
			}
		})
	}

	cfg := defaultServerConfig()
	cfg.DNSUpstreamServers = []string{"1.1.1.1", "1.1.1.1:53", "::1", "DNS.GOOGLE.", "dns.google:53"}
	final, err := finalizeServerConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(final.DNSUpstreamServers) != 3 {
		t.Fatalf("upstreams not normalized/deduplicated: %v", final.DNSUpstreamServers)
	}
}

func TestLoadServerConfigWithOverridesAppliesFlagPrecedence(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "server_config.toml")

	if err := os.WriteFile(configPath, []byte(`
PROTOCOL_TYPE = "SOCKS5"
UDP_PORT = 53
DOMAIN = ["config.example.com"]
DATA_ENCRYPTION_METHOD = 1
SUPPORTED_UPLOAD_COMPRESSION_TYPES = [0, 3]
SUPPORTED_DOWNLOAD_COMPRESSION_TYPES = [0, 3]
`), 0o644); err != nil {
		t.Fatalf("WriteFile config failed: %v", err)
	}

	cfg, err := LoadServerConfigWithOverrides(configPath, ServerConfigOverrides{
		Values: map[string]any{
			"UDPPort":                           5300,
			"Domain":                            []string{"flag.example.com", "alt.example.com"},
			"DataEncryptionMethod":              2,
			"SupportedUploadCompressionTypes":   []int{0, 1},
			"SupportedDownloadCompressionTypes": []int{0, 1, 3},
		},
	})
	if err != nil {
		t.Fatalf("LoadServerConfigWithOverrides returned error: %v", err)
	}

	if cfg.UDPPort != 5300 {
		t.Fatalf("unexpected udp port override: got=%d want=%d", cfg.UDPPort, 5300)
	}
	if len(cfg.Domain) != 2 || cfg.Domain[0] != "flag.example.com" || cfg.Domain[1] != "alt.example.com" {
		t.Fatalf("unexpected domain override: %+v", cfg.Domain)
	}
	if cfg.DataEncryptionMethod != 2 {
		t.Fatalf("unexpected data encryption override: got=%d want=%d", cfg.DataEncryptionMethod, 2)
	}
	if len(cfg.SupportedUploadCompressionTypes) != 2 || cfg.SupportedUploadCompressionTypes[0] != 0 || cfg.SupportedUploadCompressionTypes[1] != 1 {
		t.Fatalf("unexpected upload compression override: %+v", cfg.SupportedUploadCompressionTypes)
	}
	if len(cfg.SupportedDownloadCompressionTypes) != 3 {
		t.Fatalf("unexpected download compression override: %+v", cfg.SupportedDownloadCompressionTypes)
	}
}

func TestServerConfigFlagBinderBuildsOverridesForSetFlagsOnly(t *testing.T) {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	binder, err := NewServerConfigFlagBinder(fs)
	if err != nil {
		t.Fatalf("NewServerConfigFlagBinder returned error: %v", err)
	}

	if err := fs.Parse([]string{
		"-udp-port=5300",
		"-domain=a.example.com,b.example.com",
		"-use-external-socks5",
		"-supported-upload-compression-types=0,1",
		"-data-encryption-method=2",
	}); err != nil {
		t.Fatalf("flag parse failed: %v", err)
	}

	overrides := binder.Overrides()
	if got, ok := overrides.Values["UDPPort"].(int); !ok || got != 5300 {
		t.Fatalf("unexpected udp port override: %#v", overrides.Values["UDPPort"])
	}
	if got, ok := overrides.Values["UseExternalSOCKS5"].(bool); !ok || !got {
		t.Fatalf("unexpected socks5 override: %#v", overrides.Values["UseExternalSOCKS5"])
	}
	if got, ok := overrides.Values["DataEncryptionMethod"].(int); !ok || got != 2 {
		t.Fatalf("unexpected encryption method override: %#v", overrides.Values["DataEncryptionMethod"])
	}
	gotDomains, ok := overrides.Values["Domain"].([]string)
	if !ok || len(gotDomains) != 2 || gotDomains[0] != "a.example.com" || gotDomains[1] != "b.example.com" {
		t.Fatalf("unexpected domains override: %#v", overrides.Values["Domain"])
	}
	gotCompressions, ok := overrides.Values["SupportedUploadCompressionTypes"].([]int)
	if !ok || len(gotCompressions) != 2 || gotCompressions[0] != 0 || gotCompressions[1] != 1 {
		t.Fatalf("unexpected compression override: %#v", overrides.Values["SupportedUploadCompressionTypes"])
	}
	if _, exists := overrides.Values["UDPHost"]; exists {
		t.Fatalf("did not expect unset flag to appear in overrides: %#v", overrides.Values["UDPHost"])
	}
}

func TestServerConfigEffectiveSizingUsesSmartFloorsAndDerivedCapacities(t *testing.T) {
	cfg := defaultServerConfig()
	cfg.ProtocolType = "SOCKS5"
	cfg.UDPReaders = 1
	cfg.DNSRequestWorkers = 1
	cfg.DeferredSessionWorkers = 1
	cfg.DeferredSessionQueueLimit = 64
	cfg.MaxConcurrentRequests = 512
	cfg.MaxPacketsPerBatch = 1
	cfg.DNSCacheMaxRecords = 100
	cfg.ARQWindowSize = 2000

	if got := cfg.EffectiveUDPReaders(); got < 1 {
		t.Fatalf("expected effective udp readers floor, got=%d", got)
	}
	if got := cfg.EffectiveDNSRequestWorkers(); got < cfg.EffectiveUDPReaders()+1 {
		t.Fatalf("expected dns workers to track reader pressure, got=%d readers=%d", got, cfg.EffectiveUDPReaders())
	}
	if got := cfg.EffectiveDeferredSessionQueueLimit(); got < 256 {
		t.Fatalf("expected deferred queue smart floor, got=%d", got)
	}
	if got := cfg.EffectiveMaxConcurrentRequests(); got < 4096 {
		t.Fatalf("expected max concurrent requests smart floor, got=%d", got)
	}
	if got := cfg.EffectiveMaxPacketsPerBatch(); got < 10 {
		t.Fatalf("expected max packets per batch smart floor, got=%d", got)
	}
	if got := cfg.EffectiveDNSCacheMaxRecords(); got < cfg.EffectiveMaxConcurrentRequests()*2 {
		t.Fatalf("expected dns cache smart floor, got=%d concurrent=%d", got, cfg.EffectiveMaxConcurrentRequests())
	}
	if got := cfg.EffectiveSessionOrphanQueueInitialCap(); got < 32 {
		t.Fatalf("expected derived orphan queue cap, got=%d", got)
	}
	if got := cfg.EffectiveStreamQueueInitialCapacity(); got < 32 {
		t.Fatalf("expected derived stream queue cap, got=%d", got)
	}
	if got := cfg.EffectiveDNSFragmentStoreCapacity(); got < 64 {
		t.Fatalf("expected derived dns fragment store cap, got=%d", got)
	}
	if got := cfg.EffectiveSOCKS5FragmentStoreCapacity(); got < 64 {
		t.Fatalf("expected derived socks5 fragment store cap, got=%d", got)
	}
}

func TestServerConfigRequestQueueIsBoundedByPacketMemory(t *testing.T) {
	cfg := defaultServerConfig()
	cfg.MaxConcurrentRequests = 131072
	cfg.MaxPacketSize = 65535

	capacity := cfg.EffectiveRequestQueueCapacity()
	if capacity >= cfg.EffectiveMaxConcurrentRequests() {
		t.Fatalf("large-packet queue was not reduced: queue=%d concurrent=%d", capacity, cfg.EffectiveMaxConcurrentRequests())
	}
	if got := int64(capacity) * int64(cfg.MaxPacketSize); got > maxQueuedRequestBytes {
		t.Fatalf("queue retains %d packet bytes, limit=%d", got, maxQueuedRequestBytes)
	}
}

func TestServerConfigClientPolicyLimitsAreSafelyClamped(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "server_config.toml")

	if err := os.WriteFile(configPath, []byte(`
PROTOCOL_TYPE = "SOCKS5"
UDP_PORT = 53
DOMAIN = ["config.example.com"]
DATA_ENCRYPTION_METHOD = 1
SUPPORTED_UPLOAD_COMPRESSION_TYPES = [0, 3]
SUPPORTED_DOWNLOAD_COMPRESSION_TYPES = [0, 3]
MAX_ALLOWED_CLIENT_PACKET_DUPLICATION_COUNT = 999
MAX_ALLOWED_CLIENT_SETUP_PACKET_DUPLICATION_COUNT = 999
MAX_ALLOWED_CLIENT_ACTIVE_SESSION = 999
MAX_ALLOWED_CLIENT_ACTIVE_STREAMS_PER_SESSION = 999999
MAX_ALLOWED_CLIENT_UPLOAD_MTU = 999
MAX_ALLOWED_CLIENT_DOWNLOAD_MTU = 999999
MAX_ALLOWED_CLIENT_RX_TX_WORKERS = 999
MIN_ALLOWED_CLIENT_PING_AGGRESSIVE_INTERVAL_SECONDS = 0.001
MAX_ALLOWED_CLIENT_PACKETS_PER_BATCH = 999
MAX_ALLOWED_CLIENT_ARQ_WINDOW_SIZE = 999999
MAX_ALLOWED_CLIENT_ARQ_DATA_NACK_MAX_GAP = 999
MIN_ALLOWED_CLIENT_COMPRESSION_MIN_SIZE = 999999
MIN_ALLOWED_CLIENT_ARQ_INITIAL_RTO_SECONDS = 0.001
`), 0o644); err != nil {
		t.Fatalf("WriteFile config failed: %v", err)
	}

	cfg, err := LoadServerConfig(configPath)
	if err != nil {
		t.Fatalf("LoadServerConfig returned error: %v", err)
	}

	if cfg.ClientMaxPacketDuplicationCount != 15 {
		t.Fatalf("unexpected packet duplication clamp: got=%d want=%d", cfg.ClientMaxPacketDuplicationCount, 15)
	}
	if cfg.ClientMaxSetupDuplicationCount != 15 {
		t.Fatalf("unexpected setup duplication clamp: got=%d want=%d", cfg.ClientMaxSetupDuplicationCount, 15)
	}
	if cfg.MaxAllowedClientActiveSessions != 255 {
		t.Fatalf("unexpected active session clamp: got=%d want=%d", cfg.MaxAllowedClientActiveSessions, 255)
	}
	if cfg.MaxAllowedClientActiveStreams != 65535 {
		t.Fatalf("unexpected active streams clamp: got=%d want=%d", cfg.MaxAllowedClientActiveStreams, 65535)
	}
	if cfg.ClientMaxUploadMTU != 255 {
		t.Fatalf("unexpected upload mtu clamp: got=%d want=%d", cfg.ClientMaxUploadMTU, 255)
	}
	if cfg.ClientMaxDownloadMTU != 65535 {
		t.Fatalf("unexpected download mtu clamp: got=%d want=%d", cfg.ClientMaxDownloadMTU, 65535)
	}
	if cfg.ClientMaxRxTxWorkers != 255 {
		t.Fatalf("unexpected worker clamp: got=%d want=%d", cfg.ClientMaxRxTxWorkers, 255)
	}
	if cfg.ClientMinPingAggressiveInterval != 0.05 {
		t.Fatalf("unexpected ping interval clamp: got=%f want=%f", cfg.ClientMinPingAggressiveInterval, 0.05)
	}
	if cfg.ClientMaxPacketsPerBatch != 255 {
		t.Fatalf("unexpected packets per batch clamp: got=%d want=%d", cfg.ClientMaxPacketsPerBatch, 255)
	}
	if cfg.ClientMaxARQWindowSize != 8000 {
		t.Fatalf("unexpected arq window clamp: got=%d want=%d", cfg.ClientMaxARQWindowSize, 8000)
	}
	if cfg.ClientMaxARQDataNackMaxGap != 255 {
		t.Fatalf("unexpected arq nack gap clamp: got=%d want=%d", cfg.ClientMaxARQDataNackMaxGap, 255)
	}
	if cfg.ClientMinCompressionMinSize != 65535 {
		t.Fatalf("unexpected compression min size clamp: got=%d want=%d", cfg.ClientMinCompressionMinSize, 65535)
	}
	if cfg.ClientMinARQInitialRTOSeconds != 0.05 {
		t.Fatalf("unexpected arq initial rto clamp: got=%f want=%f", cfg.ClientMinARQInitialRTOSeconds, 0.05)
	}
}

func TestLoadServerConfigFallsBackToJSONWhenTOMLIsMissing(t *testing.T) {
	dir := t.TempDir()

	configPath := filepath.Join(dir, "server_config.toml")
	jsonPath := filepath.Join(dir, "server_config.json")

	if err := os.WriteFile(jsonPath, []byte(`{
  "PROTOCOL_TYPE": "SOCKS5",
  "UDP_PORT": 5300,
  "DOMAIN": ["json.example.com"],
  "DATA_ENCRYPTION_METHOD": 1,
  "SUPPORTED_UPLOAD_COMPRESSION_TYPES": [0, 3],
  "SUPPORTED_DOWNLOAD_COMPRESSION_TYPES": [0, 3]
}`), 0o644); err != nil {
		t.Fatalf("WriteFile JSON config failed: %v", err)
	}

	cfg, err := LoadServerConfig(configPath)
	if err != nil {
		t.Fatalf("LoadServerConfig returned error: %v", err)
	}

	if cfg.ConfigPath != jsonPath {
		t.Fatalf("expected JSON fallback path: got=%q want=%q", cfg.ConfigPath, jsonPath)
	}
	if cfg.UDPPort != 5300 {
		t.Fatalf("unexpected JSON UDP port: got=%d want=%d", cfg.UDPPort, 5300)
	}
}

func TestLoadServerConfigFromJSONBase64AppliesDefaults(t *testing.T) {
	rawJSON := `{
  "PROTOCOL_TYPE": "SOCKS5",
  "UDP_PORT": 5301,
  "DOMAIN": ["base64.example.com"],
  "DATA_ENCRYPTION_METHOD": 1,
  "SUPPORTED_UPLOAD_COMPRESSION_TYPES": [0, 3],
  "SUPPORTED_DOWNLOAD_COMPRESSION_TYPES": [0, 3]
}`
	encoded := base64.StdEncoding.EncodeToString([]byte(rawJSON))

	cfg, err := LoadServerConfigFromJSONBase64(encoded)
	if err != nil {
		t.Fatalf("LoadServerConfigFromJSONBase64 returned error: %v", err)
	}

	if cfg.ConfigPath != "<json_base64>" {
		t.Fatalf("unexpected config path: got=%q want=%q", cfg.ConfigPath, "<json_base64>")
	}
	if cfg.UDPPort != 5301 {
		t.Fatalf("unexpected JSON base64 UDP port: got=%d want=%d", cfg.UDPPort, 5301)
	}
	if cfg.MaxPacketsPerBatch != defaultServerConfig().MaxPacketsPerBatch {
		t.Fatalf("expected default max packets per batch to apply: got=%d want=%d", cfg.MaxPacketsPerBatch, defaultServerConfig().MaxPacketsPerBatch)
	}
}

func TestLoadServerConfigFromJSONBase64WithOverridesAppliesBeforeFinalize(t *testing.T) {
	rawJSON := `{
  "PROTOCOL_TYPE": "SOCKS5",
  "UDP_PORT": 5301,
  "DATA_ENCRYPTION_METHOD": 1,
  "SUPPORTED_UPLOAD_COMPRESSION_TYPES": [0, 3],
  "SUPPORTED_DOWNLOAD_COMPRESSION_TYPES": [0, 3]
}`
	encoded := base64.StdEncoding.EncodeToString([]byte(rawJSON))

	cfg, err := LoadServerConfigFromJSONBase64WithOverrides(encoded, ServerConfigOverrides{
		Values: map[string]any{
			"Domain": []string{"override.example.com"},
		},
	})
	if err != nil {
		t.Fatalf("LoadServerConfigFromJSONBase64WithOverrides returned error: %v", err)
	}

	if len(cfg.Domain) != 1 || cfg.Domain[0] != "override.example.com" {
		t.Fatalf("unexpected override domain: %+v", cfg.Domain)
	}
}
