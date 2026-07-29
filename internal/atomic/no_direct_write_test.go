package atomic

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestProductionCodeHasNoDirectWriteFile enforces the repository rule that
// every production file write goes through this package.
func TestProductionCodeHasNoDirectWriteFile(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	for _, tree := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, tree), func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			data, err := os.ReadFile(path) //nolint:gosec // repository source audit
			if err != nil {
				return err
			}
			if bytes.Contains(data, []byte("os.WriteFile(")) {
				t.Errorf("%s calls os.WriteFile directly; use internal/atomic", path)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("audit production writes under %s: %v", tree, err)
		}
	}
}
