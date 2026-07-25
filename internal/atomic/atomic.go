// Package atomic writes files atomically: content is written to a temp file in
// the same directory, fsync'd, and renamed over the destination, so a reader
// (or a crash) never observes a half-written file. The parent directory is
// fsync'd after the rename so the new name is durable.
package atomic

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteFile atomically writes data to path with the given permissions. On any
// error the destination is left untouched and no temp file is left behind.
//
// Plaintext-secret callers must pass 0600.
func WriteFile(path string, data []byte, perm os.FileMode) (err error) {
	dir := filepath.Dir(path)

	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("atomic write %s: create temp file: %w", path, err)
	}
	tmpName := tmp.Name()

	// On any failure past this point, remove the temp file. os.Remove of an
	// already-renamed temp is a harmless no-op.
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()

	if _, err = tmp.Write(data); err != nil {
		return fmt.Errorf("atomic write %s: write temp file: %w", path, err)
	}
	if err = tmp.Sync(); err != nil {
		return fmt.Errorf("atomic write %s: fsync temp file: %w", path, err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("atomic write %s: close temp file: %w", path, err)
	}
	// CreateTemp makes the file 0600; apply the caller's mode explicitly.
	if err = os.Chmod(tmpName, perm); err != nil {
		return fmt.Errorf("atomic write %s: chmod temp file: %w", path, err)
	}
	if err = os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("atomic write %s: rename into place: %w", path, err)
	}
	// The rename is only durable once the directory entry is fsync'd.
	if err = fsyncDir(dir); err != nil {
		return fmt.Errorf("atomic write %s: fsync directory: %w", path, err)
	}
	return nil
}
