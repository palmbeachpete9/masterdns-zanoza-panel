package main

const (
	EnvConfig     = "ZANOZA_CONFIG"
	EnvRuntimeDir = "ZANOZA_RUNTIME_DIR"

	EnvPanelAddr = "ZANOZA_PANEL_ADDR"
	EnvPanelPort = "ZANOZA_PANEL_PORT"
	EnvPanelPath = "ZANOZA_PANEL_PATH"
	EnvTLSCert   = "ZANOZA_TLS_CERT"
	EnvTLSKey    = "ZANOZA_TLS_KEY"
	EnvName      = "ZANOZA_NAME"

	EnvUser     = "ZANOZA_USER"
	EnvPassword = "ZANOZA_PASSWORD"

	EnvMasterdnsBin = "ZANOZA_MASTERDNS_BIN"

	EnvDNSHost     = "ZANOZA_DNS_HOST"
	EnvDNSPort     = "ZANOZA_DNS_PORT"
	EnvDNSUpstream = "ZANOZA_DNS_UPSTREAM"

	// EnvExternalOrigin is the externally-visible origin (e.g. behind a
	// TLS-terminating reverse proxy), like "https://panel.example". When set,
	// CSRF/origin checks validate against it and cookie Secure is derived from
	// it instead of the internal listener scheme (V4-03).
	EnvExternalOrigin = "ZANOZA_EXTERNAL_ORIGIN"
)
