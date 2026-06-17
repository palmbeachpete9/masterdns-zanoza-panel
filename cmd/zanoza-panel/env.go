package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
)

func envDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// applyEnvOverrides overrides cfg fields from ZANOZA_* env vars.
func applyEnvOverrides(cfg *Config) error {
	if v := os.Getenv(EnvPanelAddr); v != "" {
		cfg.PanelAddr = v
	}
	if v := os.Getenv(EnvPanelPort); v != "" {
		port, err := strconv.Atoi(v)
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("invalid %s=%q: want a port in 1..65535", EnvPanelPort, v)
		}
		cfg.PanelPort = port
	}
	if v := os.Getenv(EnvPanelPath); v != "" {
		path, err := normalizePanelPath(v)
		if err != nil {
			return fmt.Errorf("invalid %s=%q: %w", EnvPanelPath, v, err)
		}
		cfg.PanelPath = path
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
	return nil
}

// maybeAutoSetup creates admin from ZANOZA_USER/ZANOZA_PASSWORD on first run.
func maybeAutoSetup(creds *credentials) {
	// Never pass the bootstrap password to the supervised MasterDNS child.
	// Environment-based bootstrap is retained for deployment compatibility, but
	// the secret is no longer needed after this point.
	pass := os.Getenv(EnvPassword)
	_ = os.Unsetenv(EnvPassword)
	if !creds.setupRequired() {
		return
	}
	user := strings.TrimSpace(os.Getenv(EnvUser))
	if user == "" || pass == "" {
		return
	}
	if err := creds.set(user, pass); err != nil {
		log.Printf("auto-setup credentials failed: %v", err)
		return
	}
	log.Printf("auto-setup created admin user %q", user)
}
