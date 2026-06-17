package security

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"masterdnsvpn-go/internal/config"
)

func TestEnsureServerEncryptionKeyTightensExistingMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "encrypt_key.txt")
	if err := os.WriteFile(path, []byte("12345678901234567890123456789012"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.ServerConfig{ConfigDir: dir, EncryptionKeyFile: filepath.Base(path), DataEncryptionMethod: 1}
	info, err := EnsureServerEncryptionKey(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Loaded {
		t.Fatal("valid existing key was not loaded")
	}
	stat, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := stat.Mode().Perm(); got != 0o600 {
		t.Fatalf("key mode = %o, want 600", got)
	}
}

func TestEnsureServerEncryptionKeyConcurrentCreationUsesOnePublishedKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "encrypt_key.txt")
	cfg := config.ServerConfig{
		ConfigDir:            filepath.Dir(path),
		EncryptionKeyFile:    filepath.Base(path),
		DataEncryptionMethod: 1,
	}

	const callers = 32
	results := make(chan EncryptionKeyInfo, callers)
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			info, err := EnsureServerEncryptionKey(cfg)
			results <- info
			errs <- err
		}()
	}
	wg.Wait()
	close(results)
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent key creation failed: %v", err)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	published := string(raw)
	generated := 0
	for info := range results {
		if info.Key != published {
			t.Fatalf("caller returned unpublished key %q, published %q", info.Key, published)
		}
		if info.Generated {
			generated++
		}
	}
	if generated != 1 {
		t.Fatalf("generated count = %d, want exactly one publisher", generated)
	}
}

func TestEnsureServerEncryptionKeyRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("do-not-change"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "encrypt_key.txt")
	if err := os.Symlink(victim, path); err != nil {
		t.Fatal(err)
	}
	cfg := config.ServerConfig{ConfigDir: dir, EncryptionKeyFile: filepath.Base(path), DataEncryptionMethod: 1}
	if _, err := EnsureServerEncryptionKey(cfg); err == nil {
		t.Fatal("symlink key path was accepted")
	}
	raw, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "do-not-change" {
		t.Fatalf("symlink target was modified: %q", raw)
	}
}

func TestEnsureServerEncryptionKeyRejectsInvalidExistingKeyWithoutRotating(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "encrypt_key.txt")
	if err := os.WriteFile(path, []byte("short"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.ServerConfig{ConfigDir: dir, EncryptionKeyFile: filepath.Base(path), DataEncryptionMethod: 1}
	if _, err := EnsureServerEncryptionKey(cfg); err == nil {
		t.Fatal("invalid existing key was silently rotated")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "short" {
		t.Fatalf("invalid existing key was modified: %q", raw)
	}
	matches, err := filepath.Glob(filepath.Join(dir, ".encrypt_key.txt.tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary key files left behind: %v", matches)
	}
}

func TestEnsureServerEncryptionKeyRejectsOversizedExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "encrypt_key.txt")
	if err := os.WriteFile(path, make([]byte, maxEncryptionKeyFileBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.ServerConfig{ConfigDir: dir, EncryptionKeyFile: filepath.Base(path), DataEncryptionMethod: 1}
	if _, err := EnsureServerEncryptionKey(cfg); err == nil {
		t.Fatal("oversized existing key file was accepted")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != maxEncryptionKeyFileBytes+1 {
		t.Fatalf("oversized existing key file was modified: size=%d", info.Size())
	}
}
