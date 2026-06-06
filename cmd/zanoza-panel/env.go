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
	if v := os.Getenv(EnvPanelAddr); v != "" {
		cfg.PanelAddr = v
	}
	if v := os.Getenv(EnvPanelPort); v != "" {
		if port, err := strconv.Atoi(v); err == nil && port > 0 && port <= 65535 {
			cfg.PanelPort = port
		}
	}
	if v := os.Getenv(EnvPanelPath); v != "" {
		cfg.PanelPath = v
	}
	if v := os.Getenv(EnvTLSCert); v != "" {
		cfg.TLSCert = v
	}
	if v := os.Getenv(EnvTLSKey); v != "" {
		cfg.TLSKey = v
	}
	if v := os.Getenv(EnvName); v != "" {
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
	user := os.Getenv(EnvUser)
	pass := os.Getenv(EnvPassword)
	if user == "" || pass == "" {
		return
	}
	if err := creds.set(user, pass); err != nil {
		log.Printf("auto-setup credentials failed: %v", err)
	}
}
