package main

import (
	"log"
	"os"
	"strconv"
)

func envDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// applyEnvOverrides overrides cfg fields from ZANOZA_* env vars.
func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv(EnvPanelAddr); v != "" {
		cfg.PanelAddr = v
	}
	if v := os.Getenv(EnvPanelPort); v != "" {
		if port, err := strconv.Atoi(v); err == nil && port > 0 && port <= 65535 {
			cfg.PanelPort = port
		} else {
			log.Printf("invalid %s=%q, using config default", EnvPanelPort, v)
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

// maybeAutoSetup creates admin from ZANOZA_USER/ZANOZA_PASSWORD on first run.
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
