//go:build !windows

package atomic

import "os"

// createTemp creates the temp file with os.CreateTemp, which uses mode 0600, so
// the file is owner-only before any content is written. WriteFile applies the
// caller's final mode afterwards.
func createTemp(dir, prefix string, _ os.FileMode) (*os.File, error) {
	return os.CreateTemp(dir, prefix+"*")
}
