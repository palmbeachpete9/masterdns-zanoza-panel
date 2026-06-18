package dnscache

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewClampsExcessiveRecordLimit(t *testing.T) {
	store := New(int(^uint(0)>>1), time.Hour, time.Second)
	if store.maxRecords != maxCacheRecords {
		t.Fatalf("maxRecords = %d, want %d", store.maxRecords, maxCacheRecords)
	}
}

func TestStore_BinaryPersistence(t *testing.T) {
	tempFile := filepath.Join(t.TempDir(), "test_cache.bin")

	s := New(100, time.Hour, time.Minute)
	now := time.Now()

	// Add some entries
	keys := []string{
		BuildKey("example.com", 1, 1),
		BuildKey("google.com", 28, 1),
		BuildKey("github.com", 1, 1),
	}

	s.SetReady(keys[0], "example.com", 1, 1, []byte("\x00\x00answer1"), time.Hour, now)
	s.SetReady(keys[1], "google.com", 28, 1, []byte("\x00\x00answer2"), time.Hour, now)
	s.LookupOrCreatePending(keys[2], "github.com", 1, 1, now)

	// Save to file
	saved, err := s.SaveToFile(tempFile, now)
	if err != nil {
		t.Fatalf("SaveToFile failed: %v", err)
	}
	if saved != 2 { // Only ready entries are saved
		t.Errorf("Expected 2 saved entries, got %d", saved)
	}

	// Load into a new store
	s2 := New(100, time.Hour, time.Minute)
	loaded, err := s2.LoadFromFile(tempFile, now)
	if err != nil {
		t.Fatalf("LoadFromFile failed: %v", err)
	}
	if loaded != 2 {
		t.Errorf("Expected 2 loaded entries, got %d", loaded)
	}

	// Verify entries
	for i := 0; i < 2; i++ {
		res, ok := s2.GetReady(keys[i], []byte("\x12\x34"), now)
		if !ok {
			t.Errorf("Entry %d not found in s2", i)
			continue
		}
		if string(res[:2]) != "\x12\x34" {
			t.Errorf("Entry %d ID not patched correctly", i)
		}
	}

	// github.com was pending, should NOT be in s2
	_, ok := s2.GetReady(keys[2], []byte("\x12\x34"), now)
	if ok {
		t.Errorf("Pending entry should not have been persisted")
	}
}

func TestStore_Sharding(t *testing.T) {
	now := time.Now()

	// Fill shard-limited capacity
	// Since maxRecords is 10, each shard gets 10/32 = 0?
	// Ah, I set limit to maxRecords/shardCount in code.
	// If maxRecords is 10, limit is 0 (set to 1).

	// Let's use more records
	s := New(100, time.Hour, time.Minute) // 100/32 = 3 per shard

	for i := 0; i < 200; i++ {
		domain := "domain" + string(rune(i))
		key := BuildKey(domain, 1, 1)
		s.SetReady(key, domain, 1, 1, []byte("\x00\x00resp"), time.Hour, now)
	}

	// Verify we didn't exceed a reasonable total (accounting for shard distribution)
	count := 0
	for i := 0; i < shardCount; i++ {
		count += len(s.shards[i].items)
	}

	// Shards have a limit of maxRecords/shardCount.
	// If 100/32 = 3, each bucket has max 3 items.
	// 3 * 32 = 96.
	if count > 100 {
		t.Errorf("Total records %d exceeded target 100", count)
	}
}

func TestStoreLoadFromFileFailsOnCorruptEntry(t *testing.T) {
	tempDir := t.TempDir()
	cachePath := filepath.Join(tempDir, "corrupt_cache.bin")

	s := New(100, time.Hour, time.Minute)
	now := time.Now()
	key := BuildKey("example.com", 1, 1)
	s.SetReady(key, "example.com", 1, 1, []byte("\x00\x00answer1"), time.Hour, now)

	if _, err := s.SaveToFile(cachePath, now); err != nil {
		t.Fatalf("SaveToFile failed: %v", err)
	}

	file, err := os.OpenFile(cachePath, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		t.Fatalf("OpenFile failed: %v", err)
	}
	if _, err := file.Write([]byte{0x44, 0x4E, 0x53, 0x43, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0xAA}); err != nil {
		_ = file.Close()
		t.Fatalf("Write failed: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	s2 := New(100, time.Hour, time.Minute)
	loaded, err := s2.LoadFromFile(cachePath, now)
	if err == nil {
		t.Fatal("expected LoadFromFile to fail on corrupt entry")
	}
	if loaded != 0 {
		t.Fatalf("expected zero loaded entries on corrupt file, got %d", loaded)
	}
	if _, ok := s2.GetReady(key, []byte("\x12\x34"), now); ok {
		t.Fatal("expected corrupt load not to retain partially loaded cache entries")
	}
}

func TestStoreSaveCreatesPrivateParentAndFile(t *testing.T) {
	root := t.TempDir()
	cachePath := filepath.Join(root, "nested", "cache.bin")
	s := New(100, time.Hour, time.Minute)
	now := time.Now()
	s.SetReady(BuildKey("example.com", 1, 1), "example.com", 1, 1, []byte("\x00\x00answer"), time.Hour, now)

	if _, err := s.SaveToFile(cachePath, now); err != nil {
		t.Fatalf("SaveToFile failed: %v", err)
	}
	info, err := os.Stat(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("cache mode = %o, want 600", info.Mode().Perm())
	}
}

func TestStoreCorruptLoadPreservesLiveCache(t *testing.T) {
	now := time.Now()
	s := New(100, time.Hour, time.Minute)
	liveKey := BuildKey("live.example", 1, 1)
	s.SetReady(liveKey, "live.example", 1, 1, []byte("\x00\x00live"), time.Hour, now)

	path := filepath.Join(t.TempDir(), "corrupt-later.bin")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := binary.Write(file, binary.BigEndian, binaryMagic); err != nil {
		t.Fatal(err)
	}
	if err := binary.Write(file, binary.BigEndian, binaryVersion); err != nil {
		t.Fatal(err)
	}
	if err := binary.Write(file, binary.BigEndian, uint32(2)); err != nil {
		t.Fatal(err)
	}
	entry := Entry{
		Domain:        "first.example",
		QuestionType:  1,
		QuestionClass: 1,
		Status:        StatusReady,
		CreatedAt:     now,
		LastUsedAt:    now,
		ExpiresAt:     now.Add(time.Hour),
		Response:      []byte("\x00\x00first"),
	}
	if err := writeBinaryEntry(file, BuildKey(entry.Domain, 1, 1), &entry); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte{0xff}); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := s.LoadFromFile(path, now); err == nil {
		t.Fatal("expected corrupt load to fail")
	}
	if _, ok := s.GetReady(liveKey, []byte("\x12\x34"), now); !ok {
		t.Fatal("corrupt load destroyed the live cache")
	}
}

func TestStoreLoadRejectsDeclaredCountMismatchAndTrailingData(t *testing.T) {
	now := time.Now()
	entry := Entry{
		Domain:        "one.example",
		QuestionType:  1,
		QuestionClass: 1,
		Status:        StatusReady,
		CreatedAt:     now,
		LastUsedAt:    now,
		ExpiresAt:     now.Add(time.Hour),
		Response:      []byte("\x00\x00one"),
	}
	for name, tc := range map[string]struct {
		count    uint32
		trailing []byte
	}{
		"missing declared entry": {count: 2},
		"trailing entry bytes":   {count: 1, trailing: []byte{0xaa}},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "cache.bin")
			file, err := os.Create(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, value := range []any{binaryMagic, binaryVersion, tc.count} {
				if err := binary.Write(file, binary.BigEndian, value); err != nil {
					t.Fatal(err)
				}
			}
			if err := writeBinaryEntry(file, BuildKey(entry.Domain, 1, 1), &entry); err != nil {
				t.Fatal(err)
			}
			if _, err := file.Write(tc.trailing); err != nil {
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := New(100, time.Hour, time.Minute).LoadFromFile(path, now); err == nil {
				t.Fatal("malformed persisted cache was accepted")
			}
		})
	}
}

func TestStoreSaveRejectsEntryFieldsThatCannotBeEncoded(t *testing.T) {
	now := time.Now()
	store := New(10, time.Hour, time.Minute)
	store.SetReady("key", "oversized.example", 1, 1, make([]byte, int(^uint16(0))+1), time.Hour, now)
	if _, err := store.SaveToFile(filepath.Join(t.TempDir(), "cache.bin"), now); err == nil {
		t.Fatal("oversized response was silently length-truncated")
	}
}

func TestStoreRefusesResponsesBeyondGlobalByteBudget(t *testing.T) {
	now := time.Now()
	store := New(100, time.Hour, time.Minute)
	store.maxResponseBytes = 8
	key := BuildKey("large.example", 1, 1)
	store.SetReady(key, "large.example", 1, 1, []byte("\x00\x00oversized"), time.Hour, now)
	if _, ok := store.GetReady(key, []byte("\x12\x34"), now); ok {
		t.Fatal("response beyond the global cache byte budget was stored")
	}
	if got := store.responseBytes.Load(); got != 0 {
		t.Fatalf("response byte accounting leaked %d bytes", got)
	}
}
