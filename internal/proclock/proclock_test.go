package proclock

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestAcquireIsExclusiveAndReleasable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "envguardian.lock")
	first, err := Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(path); !errors.Is(err, ErrLocked) {
		t.Fatalf("second Acquire error=%v, want ErrLocked", err)
	}
	if err := first.Release(); err != nil {
		t.Fatal(err)
	}
	if err := first.Release(); err != nil {
		t.Fatalf("second Release error=%v, want nil", err)
	}
	again, err := Acquire(path)
	if err != nil {
		t.Fatalf("Acquire after Release: %v", err)
	}
	if err := again.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestAcquireReportsUnopenablePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing-dir", "envguardian.lock")
	if _, err := Acquire(path); err == nil || errors.Is(err, ErrLocked) {
		t.Fatalf("Acquire in a missing directory error=%v", err)
	}
}

// TestLockIsExclusiveAcrossProcesses re-executes this test binary as a child
// that tries to take a lock the parent holds.
func TestLockIsExclusiveAcrossProcesses(t *testing.T) {
	if path := os.Getenv("PROCLOCK_CHILD_PATH"); path != "" {
		if _, err := Acquire(path); errors.Is(err, ErrLocked) {
			os.Exit(3)
		}
		os.Exit(0)
	}
	path := filepath.Join(t.TempDir(), "envguardian.lock")
	held, err := Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(os.Args[0], "-test.run=^TestLockIsExclusiveAcrossProcesses$") // #nosec G204 -- this test binary
	child.Env = append(os.Environ(), "PROCLOCK_CHILD_PATH="+path)
	err = child.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 3 {
		t.Fatalf("child acquired a lock the parent holds: %v", err)
	}
	if err := held.Release(); err != nil {
		t.Fatal(err)
	}
	child = exec.Command(os.Args[0], "-test.run=^TestLockIsExclusiveAcrossProcesses$") // #nosec G204 -- this test binary
	child.Env = append(os.Environ(), "PROCLOCK_CHILD_PATH="+path)
	if err := child.Run(); err != nil {
		t.Fatalf("child could not acquire a released lock: %v", err)
	}
}
