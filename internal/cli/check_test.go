package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// setupRepo inits a repo, writes .env, and encrypts it. Returns the identity path.
func setupRepo(t *testing.T, dir, envContent string) string {
	t.Helper()
	idPath := filepath.Join(dir, "id.txt")
	writeAgeID(t, idPath)
	if _, _, code := runCLI(t, "init", "--identity", idPath, "--name", "alice"); code != exitOK {
		t.Fatal("init failed")
	}
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(envContent), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, code := runCLI(t, "encrypt", "--identity", idPath); code != exitOK {
		t.Fatal("encrypt failed")
	}
	return idPath
}

func TestCheckAllPass(t *testing.T) {
	pinDate(t)
	dir := t.TempDir()
	t.Chdir(dir)
	idPath := setupRepo(t, dir, "A=1\nB=2\n")

	out, _, code := runCLI(t, "check", "--identity", idPath)
	if code != exitOK {
		t.Fatalf("check exit = %d, want 0\n%s", code, out)
	}
	if strings.Contains(out, "[FAIL]") {
		t.Errorf("unexpected failure in check output:\n%s", out)
	}
	for _, want := range []string{"config version", "recipients", "recipient set in sync", "ciphertext", "rotations"} {
		if !strings.Contains(out, want) {
			t.Errorf("check output missing %q:\n%s", want, out)
		}
	}
}

func TestCheckDetectsStaleCiphertext(t *testing.T) {
	pinDate(t)
	dir := t.TempDir()
	t.Chdir(dir)
	idPath := setupRepo(t, dir, "A=1\n")

	// Change the plaintext without re-encrypting.
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("A=2\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	out, _, code := runCLI(t, "check", "--identity", idPath)
	if code != exitOutOfSync {
		t.Fatalf("check exit = %d, want %d\n%s", code, exitOutOfSync, out)
	}
	if !strings.Contains(out, "STALE") {
		t.Errorf("check did not report stale ciphertext:\n%s", out)
	}
}

func TestCheckReportsAllFailures(t *testing.T) {
	pinDate(t)
	dir := t.TempDir()
	t.Chdir(dir)
	idPath := setupRepo(t, dir, "A=1\n")

	// Break two things at once: stale ciphertext AND a corrupted lock.
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("A=2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(".envguardian/lock.toml", []byte("garbage\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	out, _, code := runCLI(t, "check", "--identity", idPath)
	if code != exitOutOfSync {
		t.Fatalf("exit = %d, want %d", code, exitOutOfSync)
	}
	if !strings.Contains(out, "STALE") || !strings.Contains(out, "recipient set in sync") {
		t.Errorf("expected multiple failures reported:\n%s", out)
	}
}

func TestCheckJSON(t *testing.T) {
	pinDate(t)
	dir := t.TempDir()
	t.Chdir(dir)
	idPath := setupRepo(t, dir, "A=1\n")

	out, _, code := runCLI(t, "check", "--json", "--identity", idPath)
	if code != exitOK {
		t.Fatalf("check exit = %d", code)
	}
	var parsed struct {
		OK      bool `json:"ok"`
		Failed  int  `json:"failed"`
		Results []struct {
			Name string `json:"name"`
			OK   bool   `json:"ok"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if !parsed.OK || parsed.Failed != 0 {
		t.Errorf("json ok=%v failed=%d, want ok/0", parsed.OK, parsed.Failed)
	}
	if len(parsed.Results) == 0 {
		t.Error("no results in JSON")
	}
}

func TestCheckDetectsCiphertextLockDigestMismatch(t *testing.T) {
	pinDate(t)
	dir := t.TempDir()
	t.Chdir(dir)
	idPath := setupRepo(t, dir, "A=1\n")
	cipherPath := filepath.Join(dir, ".env.age")
	ciphertext, err := os.ReadFile(cipherPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cipherPath, append(ciphertext, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	out, _, code := runCLI(t, "check", "--identity", idPath)
	if code != exitOutOfSync {
		t.Fatalf("check exit=%d, want %d\n%s", code, exitOutOfSync, out)
	}
	if !strings.Contains(out, "does not match its lock digest") {
		t.Fatalf("check did not report ciphertext digest mismatch:\n%s", out)
	}
}
