package main

import (
	"log"
	"os"
	"strconv"
)

// envDefault returns the value of the environment variable named key, or
// fallback when the variable is unset or empty. Used to make flag defaults and
// hard-coded paths overridable for Docker / infra-as-code deploys.
func envDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// applyEnvOverrides lets ZANOZA_* environment variables win over the values
// loaded from config.json. These overrides are runtime-only: they are NOT
// persisted back to config.json, so a restart without the variables reverts to
// the saved configuration. A bad ZANOZA_PANEL_PORT is ignored (kept value) so
// a typo cannot break startup.
func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv(EnvPanelAddr); v != "" {
		cfg.PanelAddr = v
	}
	if v := os.Getenv(EnvPanelPort); v != "" {
		if port, err := strconv.Atoi(v); err == nil && port > 0 && port <= 65535 {
			cfg.PanelPort = port
		} else {
			log.Printf("ignoring invalid %s=%q (want 1..65535)", EnvPanelPort, v)
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

// maybeAutoSetup bootstraps the admin account from ZANOZA_USER / ZANOZA_PASSWORD
// on first run only. Once credentials exist it is a no-op, so the variables can
// stay in the unit file across restarts without ever overwriting a password the
// admin later changed through the UI.
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
		return
	}
	log.Printf("auto-setup: admin %q created from %s/%s", user, EnvUser, EnvPassword)
}
