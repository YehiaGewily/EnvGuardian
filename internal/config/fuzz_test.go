package config

import (
	"path/filepath"
	"strings"
	"testing"
)

// FuzzParse asserts that config parsing never panics, that every accepted
// mapping resolves inside the repository root and outside .git/, and that an
// accepted config survives an Encode→Parse cycle unchanged.
func FuzzParse(f *testing.F) {
	for _, seed := range []string{
		"version = 1\n\n[[file]]\nplaintext = \".env\"\nciphertext = \".env.age\"\n",
		"version = 1\n\n[[file]]\nplaintext = \"config/dev.env\"\nciphertext = \"config/dev.env.age\"\n\n[[file]]\nplaintext = \".env\"\nciphertext = \".env.age\"\n",
		"version = 1\n\n[[file]]\nplaintext = \"../outside\"\nciphertext = \"x.age\"\n",
		"version = 1\n\n[[file]]\nplaintext = \".git/config\"\nciphertext = \"x.age\"\n",
		"version = 1\n\n[[file]]\nplaintext = \"C:\\\\Windows\\\\x\"\nciphertext = \"x.age\"\n",
		"version = 1\n\n[[file]]\nplaintext = \"a\"\nciphertext = \"a\"\n",
		"version = 2\n",
		"version = 1\nunknown = true\n",
		"",
	} {
		f.Add([]byte(seed))
	}
	root := f.TempDir()
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		cfg, err := Parse(root, data)
		if err != nil {
			return
		}
		for _, fp := range cfg.Files {
			for _, resolved := range []string{fp.PlaintextPath, fp.CiphertextPath, fp.SignaturePath} {
				rel, relErr := filepath.Rel(resolvedRoot, resolved)
				if relErr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
					t.Fatalf("accepted mapping resolves outside the repository: %q", resolved)
				}
				first, _, _ := strings.Cut(filepath.ToSlash(rel), "/")
				if strings.EqualFold(first, ".git") {
					t.Fatalf("accepted mapping resolves inside .git: %q", resolved)
				}
			}
		}
		encoded, err := cfg.Encode()
		if err != nil {
			t.Fatalf("Encode accepted config: %v", err)
		}
		again, err := Parse(root, encoded)
		if err != nil {
			t.Fatalf("re-parse of encoded config failed: %v", err)
		}
		if len(again.Files) != len(cfg.Files) {
			t.Fatalf("mapping count changed: %d then %d", len(cfg.Files), len(again.Files))
		}
		for i := range cfg.Files {
			if cfg.Files[i].Plaintext != again.Files[i].Plaintext || cfg.Files[i].Ciphertext != again.Files[i].Ciphertext {
				t.Fatalf("mapping %d changed across Encode→Parse", i)
			}
		}
	})
}
