package main

import (
	"path/filepath"
	"testing"
)

func TestEnvDefault(t *testing.T) {
	const key = "TEST_ENV_DEFAULT_KEY"

	if got := envDefault(key, "fallback"); got != "fallback" {
		t.Fatalf("expected fallback, got %q", got)
	}
	t.Setenv(key, "from-env")
	if got := envDefault(key, "fallback"); got != "from-env" {
		t.Fatalf("expected from-env, got %q", got)
	}
}

func TestApplyEnvOverrides(t *testing.T) {
	t.Run("strings override", func(t *testing.T) {
		t.Setenv(EnvPanelAddr, "10.0.0.1")
		t.Setenv(EnvPanelPath, "/secret")
		t.Setenv(EnvName, "test-server")

		cfg := &Config{PanelAddr: "0.0.0.0", PanelPath: "/admin", Name: "Default"}
		applyEnvOverrides(cfg)

		if cfg.PanelAddr != "10.0.0.1" {
			t.Fatalf("PanelAddr: got %q", cfg.PanelAddr)
		}
		if cfg.PanelPath != "/secret" {
			t.Fatalf("PanelPath: got %q", cfg.PanelPath)
		}
		if cfg.Name != "test-server" {
			t.Fatalf("Name: got %q", cfg.Name)
		}
	})

	t.Run("port valid", func(t *testing.T) {
		t.Setenv(EnvPanelPort, "9090")
		cfg := &Config{PanelPort: 8443}
		applyEnvOverrides(cfg)
		if cfg.PanelPort != 9090 {
			t.Fatalf("PanelPort: got %d", cfg.PanelPort)
		}
	})

	t.Run("port invalid keeps default", func(t *testing.T) {
		t.Setenv(EnvPanelPort, "not-a-number")
		cfg := &Config{PanelPort: 8443}
		applyEnvOverrides(cfg)
		if cfg.PanelPort != 8443 {
			t.Fatalf("PanelPort should stay default, got %d", cfg.PanelPort)
		}
	})

	t.Run("port zero keeps default", func(t *testing.T) {
		t.Setenv(EnvPanelPort, "0")
		cfg := &Config{PanelPort: 8443}
		applyEnvOverrides(cfg)
		if cfg.PanelPort != 8443 {
			t.Fatalf("PanelPort should stay default, got %d", cfg.PanelPort)
		}
	})

	t.Run("port 65536 keeps default", func(t *testing.T) {
		t.Setenv(EnvPanelPort, "65536")
		cfg := &Config{PanelPort: 8443}
		applyEnvOverrides(cfg)
		if cfg.PanelPort != 8443 {
			t.Fatalf("PanelPort should stay default, got %d", cfg.PanelPort)
		}
	})
}

func TestMaybeAutoSetup(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, "panel.env")
	creds := loadCredentials(envPath)

	if !creds.setupRequired() {
		t.Fatal("fresh creds should require setup")
	}

	maybeAutoSetup(creds)
	if !creds.setupRequired() {
		t.Fatal("setup should still be required without env vars")
	}

	t.Setenv(EnvUser, "admin")
	t.Setenv(EnvPassword, "secret123")

	maybeAutoSetup(creds)
	if creds.setupRequired() {
		t.Fatal("setup should be completed after auto-setup")
	}
	if !creds.verify("admin", "secret123") {
		t.Fatal("credentials should verify after auto-setup")
	}
}
