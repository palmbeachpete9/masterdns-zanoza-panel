package main

import (
	"os"
	"path/filepath"
)

// writeFileAtomic writes data to path durably and atomically:
//
//   - a uniquely-named temp file is created in the destination directory
//     (so concurrent writers never collide on one shared ".tmp" path);
//   - the requested mode is applied;
//   - the data is written and fsync'd;
//   - the temp file is atomically renamed over path;
//   - the destination directory is fsync'd so the rename survives a crash.
//
// On any failure the temp file is removed and the existing destination is left
// untouched, so a reader never observes a half-written file.
func writeFileAtomic(path string, data []byte, mode os.FileMode) (err error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()

	if err = tmp.Chmod(mode); err != nil {
		return err
	}
	if _, err = tmp.Write(data); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmpName, path); err != nil {
		return err
	}
	// Best-effort directory fsync so the rename is durable across a crash.
	if d, derr := os.Open(dir); derr == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
