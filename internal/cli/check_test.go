package cli

import (
	"encoding/json"
	"errors"
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
	for _, want := range []string{"config", "recipients", "lock", "ciphertext", "rotations"} {
		if !strings.Contains(out, want) {
			t.Errorf("check output missing %q:\n%s", want, out)
		}
	}
}

func TestCheckAndCheckLocalHaveSeparateResponsibilities(t *testing.T) {
	pinDate(t)
	dir := t.TempDir()
	t.Chdir(dir)
	idPath := setupRepo(t, dir, "A=1\n")

	// Change the plaintext without re-encrypting.
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("A=2\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	out, _, code := runCLI(t, "check", "--identity", idPath)
	if code != exitOK {
		t.Fatalf("repository check exit = %d, want 0\n%s", code, out)
	}
	if strings.Contains(out, "STALE") || strings.Contains(out, "out of sync") {
		t.Errorf("repository check inspected uncommitted plaintext:\n%s", out)
	}

	out, _, code = runCLI(t, "check-local", "--identity", idPath)
	if code != exitOutOfSync {
		t.Fatalf("check-local exit = %d, want %d\n%s", code, exitOutOfSync, out)
	}
	if !strings.Contains(out, "out of sync") || !strings.Contains(out, "changed keys: [A]") {
		t.Errorf("check-local did not report key-only staleness:\n%s", out)
	}
}

func TestCheckReportsAllFailures(t *testing.T) {
	pinDate(t)
	dir := t.TempDir()
	t.Chdir(dir)
	idPath := setupRepo(t, dir, "A=1\n")

	// Break two things at once: stale plaintext AND a corrupted lock.
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("A=2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(".envguardian/lock.toml", []byte("garbage\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	out, _, code := runCLI(t, "check-local", "--identity", idPath)
	if code != exitOutOfSync {
		t.Fatalf("exit = %d, want %d", code, exitOutOfSync)
	}
	if !strings.Contains(out, "out of sync") || !strings.Contains(out, "lock") {
		t.Errorf("expected multiple failures reported:\n%s", out)
	}
}

func TestCheckRequiresIdentityUnlessStructuralOnly(t *testing.T) {
	pinDate(t)
	dir := t.TempDir()
	t.Chdir(dir)
	setupRepo(t, dir, "A=1\n")
	t.Setenv("ENVGUARDIAN_IDENTITY", "")

	_, _, code := runCLI(t, "check", "--identity", filepath.Join(dir, "missing-identity"))
	if code != exitIdentity {
		t.Fatalf("check without usable identity exit=%d, want %d", code, exitIdentity)
	}
	out, _, code := runCLI(t, "check", "--structural-only")
	if code != exitOK || !strings.Contains(out, "explicit --structural-only") {
		t.Fatalf("structural-only check exit=%d\n%s", code, out)
	}
}

func TestCheckLocalMissingPlaintextPolicy(t *testing.T) {
	pinDate(t)
	dir := t.TempDir()
	t.Chdir(dir)
	idPath := setupRepo(t, dir, "A=1\n")
	if err := os.Remove(filepath.Join(dir, ".env")); err != nil {
		t.Fatal(err)
	}

	if _, _, code := runCLI(t, "check-local", "--identity", idPath); code != exitOutOfSync {
		t.Fatalf("check-local missing plaintext exit=%d, want %d", code, exitOutOfSync)
	}
	out, _, code := runCLI(t, "check-local", "--identity", idPath, "--allow-missing")
	if code != exitOK || !strings.Contains(out, "explicitly allowed") {
		t.Fatalf("check-local --allow-missing exit=%d\n%s", code, out)
	}
}

func TestCheckUnreadableRotationLedgerFails(t *testing.T) {
	pinDate(t)
	dir := t.TempDir()
	t.Chdir(dir)
	idPath := setupRepo(t, dir, "A=1\n")
	if err := os.Mkdir(filepath.Join(dir, ".envguardian", "rotation.toml"), 0o700); err != nil {
		t.Fatal(err)
	}
	out, _, code := runCLI(t, "check", "--identity", idPath)
	if code != exitConfig || !strings.Contains(out, "cannot read rotation ledger") {
		t.Fatalf("unreadable rotation ledger exit=%d\n%s", code, out)
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

func TestMissingSignatureFailsClosed(t *testing.T) {
	pinDate(t)
	dir := t.TempDir()
	t.Chdir(dir)
	idPath := setupRepo(t, dir, "A=1\n")
	if err := os.Remove(filepath.Join(dir, ".env.age.sig")); err != nil {
		t.Fatal(err)
	}
	out, _, code := runCLI(t, "check", "--identity", idPath)
	if code != exitSignature || !strings.Contains(out, "[FAIL]") || !strings.Contains(out, missingSignatureFailure) {
		t.Fatalf("unsigned check exit=%d\n%s", code, out)
	}
	if err := os.Remove(filepath.Join(dir, ".env")); err != nil {
		t.Fatal(err)
	}
	_, stderr, code := runCLI(t, "decrypt", "--identity", idPath)
	if code != exitSignature || !strings.Contains(stderr, missingSignatureFailure) {
		t.Fatalf("unsigned decrypt exit=%d stderr=%s", code, stderr)
	}
}

func TestInvalidSignatureUsesDedicatedExitAndDoesNotWrite(t *testing.T) {
	pinDate(t)
	dir := t.TempDir()
	t.Chdir(dir)
	idPath := setupRepo(t, dir, "A=SENTINEL-PLAINTEXT-SECRET\n")
	if err := os.WriteFile(filepath.Join(dir, ".env.age.sig"), []byte("invalid detached signature\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, ".env")); err != nil {
		t.Fatal(err)
	}
	_, stderr, code := runCLI(t, "decrypt", "--identity", idPath)
	if code != exitSignature {
		t.Fatalf("invalid signature decrypt exit=%d, want %d; stderr=%s", code, exitSignature, stderr)
	}
	if strings.Contains(stderr, "SENTINEL-PLAINTEXT-SECRET") {
		t.Fatalf("signature error leaked plaintext: %s", stderr)
	}
	if _, err := os.Stat(filepath.Join(dir, ".env")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid signature wrote plaintext: %v", err)
	}
	out, _, code := runCLI(t, "check", "--identity", idPath)
	if code != exitSignature || !strings.Contains(out, "[FAIL] signature") {
		t.Fatalf("invalid signature check exit=%d\n%s", code, out)
	}
}
