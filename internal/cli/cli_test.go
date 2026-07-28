package cli

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/armor"
)

var update = flag.Bool("update", false, "update golden files")

// pkgDir is the package directory, captured before any test t.Chdir's away, so
// golden paths resolve correctly.
var pkgDir string

func TestMain(m *testing.M) {
	pkgDir, _ = os.Getwd()
	os.Exit(m.Run())
}

// runCLI executes the command tree in-process and returns stdout, stderr, and
// the exit code (mirroring Execute's error handling).
func runCLI(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	var out, errBuf bytes.Buffer
	root := newRootCmd(BuildInfo{Version: "test", Commit: "none", Date: "0"})
	root.SetArgs(args)
	root.SetOut(&out)
	root.SetErr(&errBuf)
	if err := root.Execute(); err != nil {
		fmt.Fprintln(&errBuf, "envguardian:", err)
		return out.String(), errBuf.String(), exitCodeFor(err)
	}
	return out.String(), errBuf.String(), exitOK
}

func assertGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join(pkgDir, "testdata", "golden", name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s (run with -update): %v", name, err)
	}
	// Normalize line endings: git may check golden files out as CRLF on Windows.
	norm := func(s string) string { return strings.ReplaceAll(s, "\r\n", "\n") }
	if norm(got) != norm(string(want)) {
		t.Errorf("golden %s mismatch:\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}

func writeAgeID(t *testing.T, path string) (recipient string) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(id.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return id.Recipient().String()
}

// pinDate fixes nowDate for the duration of a test.
func pinDate(t *testing.T) {
	t.Helper()
	orig := nowDate
	nowDate = func() string { return "2026-07-24" }
	t.Cleanup(func() { nowDate = orig })
}

func TestInitGolden(t *testing.T) {
	pinDate(t)
	dir := t.TempDir()
	t.Chdir(dir)
	idPath := filepath.Join(dir, "id.txt")
	writeAgeID(t, idPath)

	out, _, code := runCLI(t, "init", "--identity", idPath, "--name", "alice")
	if code != exitOK {
		t.Fatalf("init exit = %d, want 0", code)
	}
	assertGolden(t, "init.golden", out)

	// The scaffolded files exist and .gitignore has the plaintext.
	for _, f := range []string{".envguardian/config.toml", ".envguardian/recipients.toml", ".gitignore"} {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("expected %s to exist: %v", f, err)
		}
	}
	gi, _ := os.ReadFile(".gitignore")
	if !strings.Contains(string(gi), ".env") {
		t.Errorf(".gitignore missing .env: %q", gi)
	}
	if !strings.Contains(string(gi), ".envguardian/auto-decrypt-state.toml") {
		t.Errorf(".gitignore missing local automatic-decryption state: %q", gi)
	}
}

func TestInitRefusesOverwrite(t *testing.T) {
	pinDate(t)
	dir := t.TempDir()
	t.Chdir(dir)
	idPath := filepath.Join(dir, "id.txt")
	writeAgeID(t, idPath)

	if _, _, code := runCLI(t, "init", "--identity", idPath, "--name", "alice"); code != exitOK {
		t.Fatalf("first init exit = %d", code)
	}
	_, stderr, code := runCLI(t, "init", "--identity", idPath, "--name", "alice")
	if code != exitConfig {
		t.Errorf("second init exit = %d, want %d", code, exitConfig)
	}
	if !strings.Contains(stderr, "already initialized") {
		t.Errorf("stderr = %q, want 'already initialized'", stderr)
	}
}

func TestInitRejectsEscapingFileBeforeWriting(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	idPath := filepath.Join(dir, "id.txt")
	writeAgeID(t, idPath)

	_, stderr, code := runCLI(t, "init", "--identity", idPath, "--file", "../outside", "--name", "alice")
	if code != exitConfig {
		t.Fatalf("exit = %d, want %d; stderr=%s", code, exitConfig, stderr)
	}
	if !strings.Contains(stderr, "escapes the repository") {
		t.Fatalf("stderr missing containment reason: %s", stderr)
	}
	if _, err := os.Stat(filepath.Join(dir, ".envguardian")); !os.IsNotExist(err) {
		t.Fatalf("init wrote repository state before validating --file: %v", err)
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	pinDate(t)
	dir := t.TempDir()
	t.Chdir(dir)
	idPath := filepath.Join(dir, "id.txt")
	writeAgeID(t, idPath)

	if _, _, code := runCLI(t, "init", "--identity", idPath, "--name", "alice"); code != exitOK {
		t.Fatal("init failed")
	}
	if err := os.WriteFile(".env", []byte("API_KEY=secret\nDEBUG=true\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// First encrypt writes.
	out, _, code := runCLI(t, "encrypt", "--identity", idPath)
	if code != exitOK {
		t.Fatalf("encrypt exit = %d", code)
	}
	assertGolden(t, "encrypt.golden", out)

	// Second encrypt is idempotent.
	out2, _, _ := runCLI(t, "encrypt", "--identity", idPath)
	assertGolden(t, "encrypt_unchanged.golden", out2)

	// Remove plaintext, then decrypt restores it.
	if err := os.Remove(".env"); err != nil {
		t.Fatal(err)
	}
	out3, _, code := runCLI(t, "decrypt", "--identity", idPath)
	if code != exitOK {
		t.Fatalf("decrypt exit = %d", code)
	}
	assertGolden(t, "decrypt.golden", out3)

	got, _ := os.ReadFile(".env")
	if string(got) != "API_KEY=secret\nDEBUG=true\n" {
		t.Errorf("decrypted .env = %q", got)
	}
}

func TestEncryptRefusesUnignoredPlaintext(t *testing.T) {
	pinDate(t)
	dir := t.TempDir()
	t.Chdir(dir)
	idPath := filepath.Join(dir, "id.txt")
	writeAgeID(t, idPath)

	if _, _, code := runCLI(t, "init", "--identity", idPath, "--name", "alice"); code != exitOK {
		t.Fatal("init failed")
	}
	// Undo init's .gitignore entry so .env is no longer ignored.
	if err := os.WriteFile(".gitignore", []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(".env", []byte("A=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Refuse.
	_, stderr, code := runCLI(t, "encrypt", "--identity", idPath)
	if code != exitConfig {
		t.Errorf("exit = %d, want %d", code, exitConfig)
	}
	if !strings.Contains(stderr, "not ignored") || !strings.Contains(stderr, "--fix") {
		t.Errorf("stderr missing risk/fix guidance:\n%s", stderr)
	}
	if _, err := os.Stat(".env.age"); err == nil {
		t.Error("ciphertext was written despite refusal")
	}

	// --fix appends and proceeds.
	_, _, code = runCLI(t, "encrypt", "--identity", idPath, "--fix")
	if code != exitOK {
		t.Fatalf("encrypt --fix exit = %d", code)
	}
	gi, _ := os.ReadFile(".gitignore")
	if !strings.Contains(string(gi), ".env") {
		t.Errorf(".gitignore not fixed: %q", gi)
	}
	if _, err := os.Stat(".env.age"); err != nil {
		t.Errorf("ciphertext not written after --fix: %v", err)
	}
}

func TestAddRecipientGolden(t *testing.T) {
	pinDate(t)
	dir := t.TempDir()
	t.Chdir(dir)
	idPath := filepath.Join(dir, "id.txt")
	writeAgeID(t, idPath)

	if _, _, code := runCLI(t, "init", "--identity", idPath, "--name", "alice"); code != exitOK {
		t.Fatal("init failed")
	}
	if err := os.WriteFile(".env", []byte("A=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, code := runCLI(t, "encrypt", "--identity", idPath); code != exitOK {
		t.Fatal("encrypt failed")
	}

	bobKey := writeAgeID(t, filepath.Join(dir, "bob.txt")) // reuse to get a valid age recipient
	out, _, code := runCLI(t, "add-recipient", "--identity", idPath, "--key", bobKey, "--name", "bob")
	if code != exitOK {
		t.Fatalf("add-recipient exit = %d", code)
	}
	assertGolden(t, "add_recipient.golden", out)
}

func TestListRecipientsGolden(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	// Write a fixed recipients.toml so dates are deterministic.
	if err := os.MkdirAll(".envguardian", 0o755); err != nil {
		t.Fatal(err)
	}
	rcpt := writeAgeID(t, filepath.Join(dir, "id.txt"))
	toml := fmt.Sprintf(`[[recipient]]
name = "alice"
key = %q
source = "manual"
added_at = "2026-07-01"
added_by = "alice"

[[recipient]]
name = "bob"
key = %q
source = "github:bob"
added_at = "2026-07-24"
added_by = "alice"
`, rcpt, writeAgeID(t, filepath.Join(dir, "bob.txt")))
	if err := os.WriteFile(".envguardian/recipients.toml", []byte(toml), 0o644); err != nil {
		t.Fatal(err)
	}

	out, _, code := runCLI(t, "list-recipients")
	if code != exitOK {
		t.Fatalf("list exit = %d", code)
	}
	assertGolden(t, "list_recipients.golden", out)
}

func TestDecryptNotARecipient(t *testing.T) {
	pinDate(t)
	dir := t.TempDir()
	t.Chdir(dir)
	aPath := filepath.Join(dir, "a.txt")
	bPath := filepath.Join(dir, "b.txt")
	writeAgeID(t, aPath)
	writeAgeID(t, bPath)

	// Encrypt to A only, then try to decrypt as B.
	if _, _, code := runCLI(t, "init", "--identity", aPath, "--name", "alice"); code != exitOK {
		t.Fatal("init failed")
	}
	if err := os.WriteFile(".env", []byte("A=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, code := runCLI(t, "encrypt", "--identity", aPath); code != exitOK {
		t.Fatal("encrypt failed")
	}
	if err := os.Remove(".env"); err != nil {
		t.Fatal(err)
	}

	_, stderr, code := runCLI(t, "decrypt", "--identity", bPath)
	if code != exitIdentity {
		t.Errorf("exit = %d, want %d", code, exitIdentity)
	}
	if !strings.Contains(stderr, "not a recipient of this file") || !strings.Contains(stderr, "add-recipient") {
		t.Errorf("stderr missing guidance:\n%s", stderr)
	}
}

func TestDecryptPassphraseRequired(t *testing.T) {
	// Isolate so only the --identity flag source is viable.
	t.Setenv("ENVGUARDIAN_IDENTITY", "")
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir())

	dir := t.TempDir()
	t.Chdir(dir)
	aPath := filepath.Join(dir, "a.txt")
	writeAgeID(t, aPath)

	// Set up a valid repo so decrypt reaches identity resolution.
	if _, _, code := runCLI(t, "init", "--identity", aPath, "--name", "alice"); code != exitOK {
		t.Fatal("init failed")
	}
	if err := os.WriteFile(".env", []byte("A=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, code := runCLI(t, "encrypt", "--identity", aPath); code != exitOK {
		t.Fatal("encrypt failed")
	}

	// A passphrase-protected age identity, with no TTY attached.
	encPath := filepath.Join(dir, "enc.txt")
	writeEncryptedAgeID(t, encPath, "hunter2")

	_, stderr, code := runCLI(t, "decrypt", "--identity", encPath)
	if code != exitIdentity {
		t.Errorf("exit = %d, want %d", code, exitIdentity)
	}
	if !strings.Contains(stderr, "no TTY is attached") {
		t.Errorf("stderr missing no-TTY guidance:\n%s", stderr)
	}
}

func writeEncryptedAgeID(t *testing.T, path, passphrase string) {
	t.Helper()
	inner, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	rcpt, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	aw := armor.NewWriter(&buf)
	w, err := age.Encrypt(aw, rcpt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(inner.String() + "\n")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := aw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}
