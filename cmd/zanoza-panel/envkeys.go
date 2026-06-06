package main

// Environment-variable names recognised by the panel. Centralising them as
// constants keeps the lookup sites (env.go, main.go, process.go) in sync and
// makes the full override surface discoverable in one place.
const (
	// EnvConfig overrides the -config flag default (panel config.json path).
	EnvConfig = "ZANOZA_CONFIG"
	// EnvRuntimeDir overrides where keyring.json / server_config.toml live.
	EnvRuntimeDir = "ZANOZA_RUNTIME_DIR"

	// Panel HTTP/TLS listener overrides.
	EnvPanelAddr = "ZANOZA_PANEL_ADDR"
	EnvPanelPort = "ZANOZA_PANEL_PORT"
	EnvPanelPath = "ZANOZA_PANEL_PATH"
	EnvTLSCert   = "ZANOZA_TLS_CERT"
	EnvTLSKey    = "ZANOZA_TLS_KEY"
	EnvName      = "ZANOZA_NAME"

	// First-run unattended admin bootstrap.
	EnvUser     = "ZANOZA_USER"
	EnvPassword = "ZANOZA_PASSWORD"

	// MasterDnsVPN server binary + DNS listener defaults (first config write).
	EnvMasterdnsBin = "MASTERDNS_BIN"
	EnvDNSHost      = "ZANOZA_DNS_HOST"
	EnvDNSPort      = "ZANOZA_DNS_PORT"
	EnvDNSUpstream  = "ZANOZA_DNS_UPSTREAM"
)
