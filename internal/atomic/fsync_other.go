//go:build !windows

package atomic

import "os"

// fsyncDir fsyncs a directory so a prior rename is durable across a crash.
func fsyncDir(dir string) error {
	d, err := os.Open(dir) //nolint:gosec // G304: dir is the parent directory of the file being atomically written
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
