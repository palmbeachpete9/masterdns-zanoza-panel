package main

import (
	"log"
	"os"
	"strconv"
)

// envDefault returns the value of key from the environment, or fallback if
// the key is unset or empty.
func envDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// applyEnvOverrides applies ZANOZA_* environment variables on top of an
// already-loaded config.  Env vars take precedence over config file values.
// Call after loadConfig and before useTLS / panel-addr decisions.
func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("ZANOZA_PANEL_ADDR"); v != "" {
		cfg.PanelAddr = v
	}
	if v := os.Getenv("ZANOZA_PANEL_PORT"); v != "" {
		if port, err := strconv.Atoi(v); err == nil && port > 0 && port <= 65535 {
			cfg.PanelPort = port
		}
	}
	if v := os.Getenv("ZANOZA_PANEL_PATH"); v != "" {
		cfg.PanelPath = v
	}
	if v := os.Getenv("ZANOZA_TLS_CERT"); v != "" {
		cfg.TLSCert = v
	}
	if v := os.Getenv("ZANOZA_TLS_KEY"); v != "" {
		cfg.TLSKey = v
	}
	if v := os.Getenv("ZANOZA_NAME"); v != "" {
		cfg.Name = v
	}
	cfg.normalize()
}

// maybeAutoSetup seeds initial admin credentials from ZANOZA_USER and
// ZANOZA_PASSWORD env vars when the credentials file is empty (first run).
func maybeAutoSetup(creds *credentials) {
	if !creds.setupRequired() {
		return
	}
	user := os.Getenv("ZANOZA_USER")
	pass := os.Getenv("ZANOZA_PASSWORD")
	if user == "" || pass == "" {
		return
	}
	if err := creds.set(user, pass); err != nil {
		log.Printf("auto-setup credentials failed: %v", err)
	}
}
