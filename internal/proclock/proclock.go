// Package proclock provides an exclusive, non-blocking inter-process lock on a
// file. The operating system releases the lock when the holding process exits,
// so a crash never leaves a stale lock behind.
package proclock

import (
	"errors"
	"fmt"
	"os"
)

// ErrLocked reports that another process holds the lock.
var ErrLocked = errors.New("lock is held by another process")

// Lock is a held exclusive lock.
type Lock struct {
	file *os.File
}

// Acquire takes an exclusive lock on path, creating the file with mode 0600 if
// needed. It never waits: when another process holds the lock it returns an
// error wrapping ErrLocked. The file's content is never read or written.
func Acquire(path string) (*Lock, error) {
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) //nolint:gosec // caller-derived lock path, never written
	if err != nil {
		return nil, fmt.Errorf("open lock file %s: %w", path, err)
	}
	if err := lockFile(file); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	return &Lock{file: file}, nil
}

// Release unlocks and closes the lock file. The file itself is left in place;
// removing it would race with a process that has opened but not yet locked it.
func (l *Lock) Release() error {
	if l == nil || l.file == nil {
		return nil
	}
	unlockErr := unlockFile(l.file)
	closeErr := l.file.Close()
	l.file = nil
	if unlockErr != nil {
		return fmt.Errorf("unlock: %w", unlockErr)
	}
	return closeErr
}
