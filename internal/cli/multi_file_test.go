package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/YehiaGewily/envguardian/internal/config"
)

func TestEncryptDecryptMultipleConfiguredFiles(t *testing.T) {
	repo := gitInitRepo(t)
	identity := filepath.Join(repo, "id")
	writeAgeID(t, identity)
	if out, stderr, code := runCLIInDir(t, repo, "init", "--identity", identity, "--name", "alice"); code != exitOK {
		t.Fatalf("init: %d\n%s%s", code, out, stderr)
	}
	paths := config.PathsFor(repo)
	cfg, err := config.Load(repo, paths.Config)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Files = append(cfg.Files, config.FilePair{Plaintext: "config/worker.env", Ciphertext: "config/worker.env.age"})
	if err := cfg.Save(paths.Config); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(repo, "config"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".env"), []byte("APP_MODE=local\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "config", "worker.env"), []byte("QUEUE=local\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, stderr, code := runCLIInDir(t, repo, "encrypt", "--identity", identity, "--fix"); code != exitOK {
		t.Fatalf("multi-file encrypt: %d\n%s%s", code, out, stderr)
	}
	for _, path := range []string{".env.age", ".env.age.sig", "config/worker.env.age", "config/worker.env.age.sig"} {
		if _, err := os.Stat(filepath.Join(repo, filepath.FromSlash(path))); err != nil {
			t.Fatalf("missing %s: %v", path, err)
		}
	}
	lock, err := os.ReadFile(paths.Lock)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(lock), "[[file]]") != 2 {
		t.Fatalf("multi-file lock does not have two entries:\n%s", lock)
	}
	if out, stderr, code := runCLIInDir(t, repo, "check", "--identity", identity); code != exitOK {
		t.Fatalf("multi-file check: %d\n%s%s", code, out, stderr)
	}
	for _, path := range []string{".env", "config/worker.env"} {
		if err := os.Remove(filepath.Join(repo, filepath.FromSlash(path))); err != nil {
			t.Fatal(err)
		}
	}
	if out, stderr, code := runCLIInDir(t, repo, "decrypt", "--identity", identity); code != exitOK {
		t.Fatalf("multi-file decrypt: %d\n%s%s", code, out, stderr)
	}
	worker, err := os.ReadFile(filepath.Join(repo, "config", "worker.env"))
	if err != nil || string(worker) != "QUEUE=local\n" {
		t.Fatalf("worker plaintext = %q, %v", worker, err)
	}
}
