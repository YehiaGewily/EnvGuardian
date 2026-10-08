// Package atomic writes files atomically: content is written to a temp file in
// the same directory, fsync'd, and renamed over the destination, so a reader
// (or a crash) never observes a half-written file. The parent directory is
// fsync'd after the rename so the new name is durable.
//
// An owner-only mode (no group or other bits) is enforced on every platform: on
// Unix through the file mode, and on Windows through a protected DACL that
// grants access only to the current user and is applied when the temp file is
// created, before any content is written.
package atomic

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteFile atomically writes data to path with the given permissions. On any
// error the destination is left untouched and no temp file is left behind.
//
// Plaintext-secret callers must pass 0600. When perm grants no group or other
// access, the file is owner-only on every platform; see createTemp.
func WriteFile(path string, data []byte, perm os.FileMode) error {
	return writeFile(path, data, perm, createTemp)
}

// tempCreator exclusively creates a new temp file in dir whose name starts with
// prefix. perm is the final mode the caller asked for, so an implementation can
// restrict access at creation time. On error it must leave no file behind.
type tempCreator func(dir, prefix string, perm os.FileMode) (*os.File, error)

func writeFile(path string, data []byte, perm os.FileMode, create tempCreator) (err error) {
	dir := filepath.Dir(path)

	tmp, err := create(dir, "."+filepath.Base(path)+".tmp-", perm)
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
	// On Unix the temp file starts 0600; on Windows its ACL was fixed at
	// creation. Apply the final mode before syncing so both content and
	// metadata are durable when the file is renamed. On Windows this only
	// toggles the read-only attribute and leaves the ACL untouched.
	if err = os.Chmod(tmpName, perm); err != nil {
		return fmt.Errorf("atomic write %s: chmod temp file: %w", path, err)
	}
	if err = tmp.Sync(); err != nil {
		return fmt.Errorf("atomic write %s: fsync temp file: %w", path, err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("atomic write %s: close temp file: %w", path, err)
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
