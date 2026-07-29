package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveManagedPathRejectsUnsafeForms(t *testing.T) {
	root := t.TempDir()
	tests := []struct {
		name string
		path string
	}{
		{"empty", ""},
		{"whitespace", "   "},
		{"repository root", "."},
		{"cleaned repository root", "nested/.."},
		{"parent escape slash", "../outside"},
		{"parent escape backslash", `..\outside`},
		{"unix absolute", "/tmp/outside"},
		{"windows drive absolute", `C:\outside.env`},
		{"windows drive relative", `C:outside.env`},
		{"windows UNC", `\\server\share\outside.env`},
		{"windows extended", `\\?\C:\outside.env`},
		{"windows rooted", `\outside.env`},
		{"git hook slash", ".git/hooks/pre-commit"},
		{"git hook backslash", `.git\hooks\pre-commit`},
		{"git trailing-dot alias", ".git./hooks/pre-commit"},
		{"windows alternate stream", "safe.env:payload"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, err := ResolveManagedPath(root, tt.path); err == nil {
				t.Fatalf("ResolveManagedPath(%q) = %q, want error", tt.path, got)
			}
		})
	}
}

func TestResolveManagedPathAllowsNestedDestination(t *testing.T) {
	root := t.TempDir()
	canonicalRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ResolveManagedPath(root, "config/dev/.env")
	if err != nil {
		t.Fatalf("nested path rejected: %v", err)
	}
	want := filepath.Join(canonicalRoot, "config", "dev", ".env")
	if got != want {
		t.Fatalf("resolved = %q, want %q", got, want)
	}
}

func TestResolveManagedPathRejectsSymlinkedParentEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	link := filepath.Join(root, "linked")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if got, err := ResolveManagedPath(root, "linked/.env"); err == nil {
		t.Fatalf("symlink escape resolved to %q, want error", got)
	}
}

func TestParseRejectsMappingAliases(t *testing.T) {
	root := t.TempDir()
	tests := []struct {
		name    string
		body    string
		wantErr string
	}{
		{
			name:    "same pair destination",
			body:    "version = 1\n[[file]]\nplaintext = \"same\"\nciphertext = \"same\"\n",
			wantErr: "resolve to the same file",
		},
		{
			name:    "plaintext collides with derived signature",
			body:    "version = 1\n[[file]]\nplaintext = \"secret.age.sig\"\nciphertext = \"secret.age\"\n",
			wantErr: "signature for ciphertext",
		},
		{
			name:    "duplicate plaintext",
			body:    "version = 1\n[[file]]\nplaintext = \"a.env\"\nciphertext = \"a.age\"\n[[file]]\nplaintext = \"dir/../a.env\"\nciphertext = \"b.age\"\n",
			wantErr: "duplicate plaintext",
		},
		{
			name:    "duplicate ciphertext",
			body:    "version = 1\n[[file]]\nplaintext = \"a.env\"\nciphertext = \"shared.age\"\n[[file]]\nplaintext = \"b.env\"\nciphertext = \"dir/../shared.age\"\n",
			wantErr: "duplicate ciphertext",
		},
		{
			name:    "cross-pair collision",
			body:    "version = 1\n[[file]]\nplaintext = \"a.env\"\nciphertext = \"a.age\"\n[[file]]\nplaintext = \"b.env\"\nciphertext = \"a.env\"\n",
			wantErr: "resolve to the same file",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(root, []byte(tt.body))
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestParseResolvesPathsOnce(t *testing.T) {
	root := t.TempDir()
	canonicalRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Parse(root, []byte("version = 1\n[[file]]\nplaintext = \"config/dev/.env\"\nciphertext = \"config/dev/.env.age\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Files[0].PlaintextPath; got != filepath.Join(canonicalRoot, "config", "dev", ".env") {
		t.Fatalf("resolved plaintext = %q", got)
	}
	if got := cfg.Files[0].CiphertextPath; got != filepath.Join(canonicalRoot, "config", "dev", ".env.age") {
		t.Fatalf("resolved ciphertext = %q", got)
	}
	if got := cfg.Files[0].SignaturePath; got != filepath.Join(canonicalRoot, "config", "dev", ".env.age.sig") {
		t.Fatalf("resolved signature = %q", got)
	}
}

func TestParseAcceptsMultipleDistinctMappings(t *testing.T) {
	root := t.TempDir()
	body := "version = 1\n[[file]]\nplaintext = \"a.env\"\nciphertext = \"a.age\"\n[[file]]\nplaintext = \"b.env\"\nciphertext = \"b.age\"\n"
	cfg, err := Parse(root, []byte(body))
	if err != nil {
		t.Fatalf("Parse multi-file config: %v", err)
	}
	if len(cfg.Files) != 2 {
		t.Fatalf("file mappings = %d, want 2", len(cfg.Files))
	}
	if filepath.Base(cfg.Files[0].PlaintextPath) != "a.env" || filepath.Base(cfg.Files[1].CiphertextPath) != "b.age" {
		t.Fatalf("resolved mappings = %+v", cfg.Files)
	}
}

func TestParseRejectsVersionAndUnknownFields(t *testing.T) {
	root := t.TempDir()
	tests := []struct {
		name string
		body string
		want string
	}{
		{name: "unsupported version", body: "version = 2\n[[file]]\nplaintext = \".env\"\nciphertext = \".env.age\"\n", want: "unsupported config version"},
		{name: "unknown top-level", body: "version = 1\nsurprise = true\n[[file]]\nplaintext = \".env\"\nciphertext = \".env.age\"\n", want: "unknown config field"},
		{name: "unknown file field", body: "version = 1\n[[file]]\nplaintext = \".env\"\nciphertext = \".env.age\"\nsurprise = true\n", want: "unknown config field"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(root, []byte(tt.body))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestLoadPreservesNotExist(t *testing.T) {
	root := t.TempDir()
	_, err := Load(root, filepath.Join(root, ".envguardian", "config.toml"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Load error = %v, want errors.Is(os.ErrNotExist)", err)
	}
}

func TestPathsLoadAndSaveRoundTrip(t *testing.T) {
	root := t.TempDir()
	paths := PathsFor(root)
	if paths.Root != root || paths.Dir != filepath.Join(root, Dir) || paths.State != filepath.Join(root, Dir, AutoDecryptStateFile) || paths.Rotation != filepath.Join(root, Dir, RotationFile) {
		t.Fatalf("PathsFor returned unexpected conventional paths: %+v", paths)
	}
	if err := os.MkdirAll(paths.Dir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{Version: Version, Files: []FilePair{{Plaintext: ".env", Ciphertext: ".env.age"}}}
	if err := cfg.Save(paths.Config); err != nil {
		t.Fatalf("Save: %v", err)
	}
	loaded, err := Load(root, paths.Config)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Version != Version || len(loaded.Files) != 1 || loaded.Files[0].Plaintext != ".env" {
		t.Fatalf("round-trip config structure is wrong: %+v", loaded)
	}
}

func TestLoadRejectsMalformedExistingConfig(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "config.toml")
	if err := os.WriteFile(path, []byte("version = ["), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(root, path); err == nil || !strings.Contains(err.Error(), "is invalid") {
		t.Fatalf("Load malformed config error = %v", err)
	}
}
