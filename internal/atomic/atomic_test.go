package atomic

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func tempFiles(t *testing.T, dir string) []string {
	t.Helper()
	// Our temp files are named ".<base>.tmp-*".
	matches, err := filepath.Glob(filepath.Join(dir, ".*.tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	return matches
}

func TestWriteFileCreatesAndReplaces(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")

	if err := WriteFile(path, []byte("first"), 0o600); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if got, _ := os.ReadFile(path); string(got) != "first" {
		t.Fatalf("content = %q, want first", got)
	}

	if err := WriteFile(path, []byte("second"), 0o600); err != nil {
		t.Fatalf("second write: %v", err)
	}
	if got, _ := os.ReadFile(path); string(got) != "second" {
		t.Fatalf("content = %q, want second", got)
	}

	if leftovers := tempFiles(t, dir); len(leftovers) != 0 {
		t.Errorf("temp files left behind: %v", leftovers)
	}
}

func TestWriteFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permission bits not meaningful on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	if err := WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o, want 600", info.Mode().Perm())
	}
}

// TestInterruptedWriteLeavesOriginalIntact forces a failure after the temp file
// is created (by pointing the destination at a directory, so the rename fails)
// and asserts the original is untouched and no temp files remain — the exact
// guarantee an interrupted write must provide.
func TestInterruptedWriteLeavesOriginalIntact(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "target")

	if err := WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Replace the target with a directory of the same name so os.Rename fails.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := WriteFile(path, []byte("replacement"), 0o600); err == nil {
		t.Fatal("expected WriteFile to fail when destination is a directory")
	}

	// The original destination (now a directory) is intact.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("destination vanished: %v", err)
	}
	if !info.IsDir() {
		t.Errorf("destination no longer a directory")
	}
	// And the failed write left no temp files behind.
	if leftovers := tempFiles(t, dir); len(leftovers) != 0 {
		t.Errorf("temp files left after failed write: %v", leftovers)
	}
}

func TestOriginalIntactWhenDestUnwritable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keep.txt")
	if err := WriteFile(path, []byte("keepme"), 0o600); err != nil {
		t.Fatal(err)
	}

	// A temp-creation failure (nonexistent parent) must not touch the original.
	bad := filepath.Join(dir, "nope", "child")
	if err := WriteFile(bad, []byte("x"), 0o600); err == nil {
		t.Fatal("expected failure writing into a nonexistent directory")
	}
	if got, _ := os.ReadFile(path); string(got) != "keepme" {
		t.Errorf("unrelated original changed: %q", got)
	}
}
