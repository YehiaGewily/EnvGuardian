//go:build windows

package atomic

// fsyncDir is a no-op on Windows: directories cannot be opened and fsync'd the
// way they can on Unix, and os.Rename already uses MoveFileEx with
// MOVEFILE_REPLACE_EXISTING so the replacement is atomic.
func fsyncDir(string) error { return nil }
