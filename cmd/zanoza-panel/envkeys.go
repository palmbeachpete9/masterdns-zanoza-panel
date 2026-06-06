package main

// Environment variable names consumed by zanoza-panel.
// Centralised here — do not write string literals in os.Getenv / envDefault.
const (
	// Panel config / runtime.
	EnvConfig     = "ZANOZA_CONFIG"
	EnvRuntimeDir = "ZANOZA_RUNTIME_DIR"

	// Panel server overrides (applyEnvOverrides).
	EnvPanelAddr = "ZANOZA_PANEL_ADDR"
	EnvPanelPort = "ZANOZA_PANEL_PORT"
	EnvPanelPath = "ZANOZA_PANEL_PATH"
	EnvTLSCert   = "ZANOZA_TLS_CERT"
	EnvTLSKey    = "ZANOZA_TLS_KEY"
	EnvName      = "ZANOZA_NAME"

	// Auto-setup credentials (maybeAutoSetup).
	EnvUser     = "ZANOZA_USER"
	EnvPassword = "ZANOZA_PASSWORD"

	// MasterDnsVPN server.
	EnvMasterdnsBin = "MASTERDNS_BIN"

	// DNS server config (ensureserverConfig).
	EnvDNSHost     = "ZANOZA_DNS_HOST"
	EnvDNSPort     = "ZANOZA_DNS_PORT"
	EnvDNSUpstream = "ZANOZA_DNS_UPSTREAM"
)
