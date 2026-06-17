package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnvDefault(t *testing.T) {
	const key = "TEST_ENV_DEFAULT_KEY"

	got := envDefault(key, "fallback")
	assert.Equal(t, "fallback", got)

	t.Setenv(key, "from-env")
	got = envDefault(key, "fallback")
	assert.Equal(t, "from-env", got)
}

func TestApplyEnvOverrides(t *testing.T) {
	t.Run("strings override", func(t *testing.T) {
		t.Setenv(EnvPanelAddr, "10.0.0.1")
		t.Setenv(EnvPanelPath, "/secret")
		t.Setenv(EnvName, "test-server")

		cfg := &Config{PanelAddr: "0.0.0.0", PanelPath: "/admin", Name: "Default"}
		require.NoError(t, applyEnvOverrides(cfg))

		assert.Equal(t, "10.0.0.1", cfg.PanelAddr)
		assert.Equal(t, "/secret", cfg.PanelPath)
		assert.Equal(t, "test-server", cfg.Name)
	})

	tests := []struct {
		name     string
		env      string
		initial  int
		expected int
	}{
		{"valid", "9090", 8443, 9090},
		{"invalid string", "not-a-number", 8443, 8443},
		{"zero", "0", 8443, 8443},
		{"too large", "65536", 8443, 8443},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(EnvPanelPort, tt.env)
			cfg := &Config{PanelPort: tt.initial}
			err := applyEnvOverrides(cfg)
			if tt.name == "valid" {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, cfg.PanelPort)
			} else {
				require.Error(t, err)
				assert.Equal(t, tt.initial, cfg.PanelPort)
			}
		})
	}
}

func TestEnvironmentWithoutRemovesBootstrapPassword(t *testing.T) {
	got := environmentWithout([]string{"KEEP=value", EnvPassword + "=secret", "EMPTY="}, EnvPassword)
	if strings.Join(got, ",") != "KEEP=value,EMPTY=" {
		t.Fatalf("filtered environment = %v", got)
	}
}

func TestMaybeAutoSetup(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, "panel.env")
	creds := loadCredentials(envPath)

	require.True(t, creds.setupRequired(), "fresh creds should require setup")

	maybeAutoSetup(creds)
	require.True(t, creds.setupRequired(), "setup should still be required without env vars")

	t.Setenv(EnvUser, "admin")
	t.Setenv(EnvPassword, "secret123")

	maybeAutoSetup(creds)
	require.False(t, creds.setupRequired(), "setup should be completed after auto-setup")
	require.True(t, creds.verify("admin", "secret123"), "credentials should verify after auto-setup")
}
