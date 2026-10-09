//go:build windows

package proclock

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// lockRange covers the whole file; the lock is advisory between EnvGuardian
// processes, which never read or write the lock file's content.
const lockRange = ^uint32(0)

func lockFile(file *os.File) error {
	overlapped := new(windows.Overlapped)
	err := windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, lockRange, lockRange, overlapped)
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return ErrLocked
	}
	return err
}

func unlockFile(file *os.File) error {
	overlapped := new(windows.Overlapped)
	return windows.UnlockFileEx(windows.Handle(file.Fd()), 0, lockRange, lockRange, overlapped)
}
