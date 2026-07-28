package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/YehiaGewily/envguardian/internal/config"
)

type trustedRepo struct {
	repo     string
	bin      string
	identity string
	branch   string
	commit   string
}

func setupTrustedRepo(t *testing.T, content string) trustedRepo {
	t.Helper()
	repo := gitInitRepo(t)
	bin := buildBinary(t)
	idPath := filepath.Join(repo, "id.txt")
	writeAgeID(t, idPath)
	if out, code := run(t, repo, bin, "init", "--identity", idPath, "--name", "alice"); code != 0 {
		t.Fatalf("init: %d\n%s", code, out)
	}
	if err := os.WriteFile(filepath.Join(repo, ".env"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, code := run(t, repo, bin, "encrypt", "--identity", idPath); code != 0 {
		t.Fatalf("encrypt: %d\n%s", code, out)
	}
	for _, args := range [][]string{
		{"add", ".envguardian", ".env.age", ".gitignore"},
		{"commit", "-m", "trusted baseline"},
	} {
		if out, code := run(t, repo, "git", args...); code != 0 {
			t.Fatalf("git %v: %d\n%s", args, code, out)
		}
	}
	branch, _ := run(t, repo, "git", "branch", "--show-current")
	commit, _ := run(t, repo, "git", "rev-parse", "HEAD")
	if out, code := run(t, repo, bin, "decrypt", "--identity", idPath, "--accept-changes"); code != 0 {
		t.Fatalf("establish trust: %d\n%s", code, out)
	}
	return trustedRepo{
		repo: repo, bin: bin, identity: idPath,
		branch: strings.TrimSpace(branch), commit: strings.TrimSpace(commit),
	}
}

func TestAutoDecryptUnchangedIsSilentAndRestoresPlaintext(t *testing.T) {
	fixture := setupTrustedRepo(t, "A=1\n")
	if err := os.Remove(filepath.Join(fixture.repo, ".env")); err != nil {
		t.Fatal(err)
	}
	out, code := run(t, fixture.repo, fixture.bin, "hook-auto-decrypt", "--identity", fixture.identity)
	if code != 0 {
		t.Fatalf("unchanged auto-decrypt: %d\n%s", code, out)
	}
	if out != "" {
		t.Fatalf("unchanged auto-decrypt was not silent: %q", out)
	}
	got, err := os.ReadFile(filepath.Join(fixture.repo, ".env"))
	if err != nil || string(got) != "A=1\n" {
		t.Fatalf("plaintext not restored: %q, %v", got, err)
	}
}

func TestCheckoutWithModifiedConfigDoesNotWrite(t *testing.T) {
	fixture := setupTrustedRepo(t, "SAFE=original\n")
	if out, code := run(t, fixture.repo, "git", "checkout", "-b", "hostile-config"); code != 0 {
		t.Fatalf("create hostile branch: %d\n%s", code, out)
	}
	configPath := filepath.Join(fixture.repo, ".envguardian", "config.toml")
	maliciousConfig := "version = 1\n[[file]]\nplaintext = \"nested/.env\"\nciphertext = \".env.age\"\n"
	if err := os.WriteFile(configPath, []byte(maliciousConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, code := run(t, fixture.repo, "git", "add", ".envguardian/config.toml"); code != 0 {
		t.Fatalf("git add hostile config: %d\n%s", code, out)
	}
	if out, code := run(t, fixture.repo, "git", "commit", "-m", "change managed config"); code != 0 {
		t.Fatalf("commit hostile config: %d\n%s", code, out)
	}
	if out, code := run(t, fixture.repo, "git", "checkout", fixture.branch); code != 0 {
		t.Fatalf("return to trusted branch: %d\n%s", code, out)
	}
	if err := os.WriteFile(filepath.Join(fixture.repo, ".env"), []byte("SAFE=sentinel\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, code := run(t, fixture.repo, fixture.bin, "install-hooks"); code != 0 {
		t.Fatalf("install hooks: %d\n%s", code, out)
	}
	env := append(os.Environ(), "ENVGUARDIAN_IDENTITY="+fixture.identity)
	out, code := runEnv(t, fixture.repo, env, "git", "checkout", "hostile-config")
	if code == 0 {
		t.Fatalf("checkout succeeded despite blocked post-checkout hook:\n%s", out)
	}
	if !strings.Contains(out, "managed configuration changed") || !strings.Contains(out, "--accept-changes") {
		t.Fatalf("checkout did not explain the trust boundary:\n%s", out)
	}
	if !strings.Contains(out, "unsigned") {
		t.Fatalf("checkout did not report unsigned incoming commit:\n%s", out)
	}
	got, err := os.ReadFile(filepath.Join(fixture.repo, ".env"))
	if err != nil || string(got) != "SAFE=sentinel\n" {
		t.Fatalf("blocked checkout modified plaintext: %q, %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(fixture.repo, "nested", ".env")); !os.IsNotExist(err) {
		t.Fatalf("blocked checkout wrote incoming config destination: %v", err)
	}
}

func TestCiphertextChangeRequiresAcceptanceAndReportsKeyNames(t *testing.T) {
	fixture := setupTrustedRepo(t, "DATABASE_URL=local\n")
	if out, code := run(t, fixture.repo, "git", "checkout", "-b", "changed-ciphertext"); code != 0 {
		t.Fatalf("create branch: %d\n%s", code, out)
	}
	secretValue := "postgres://attacker.invalid/database"
	if err := os.WriteFile(filepath.Join(fixture.repo, ".env"), []byte("DATABASE_URL="+secretValue+"\nNEW_KEY=hidden-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, code := run(t, fixture.repo, fixture.bin, "encrypt", "--identity", fixture.identity); code != 0 {
		t.Fatalf("encrypt changed payload: %d\n%s", code, out)
	}
	if out, code := run(t, fixture.repo, "git", "add", ".env.age", ".envguardian/lock.toml"); code != 0 {
		t.Fatalf("stage ciphertext: %d\n%s", code, out)
	}
	if out, code := run(t, fixture.repo, "git", "commit", "-m", "change encrypted config"); code != 0 {
		t.Fatalf("commit ciphertext: %d\n%s", code, out)
	}
	current, _ := run(t, fixture.repo, "git", "rev-parse", "HEAD")
	if err := os.WriteFile(filepath.Join(fixture.repo, ".env"), []byte("DATABASE_URL=sentinel\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	out, code := run(t, fixture.repo, fixture.bin, "hook-auto-decrypt", "--identity", fixture.identity)
	if code == 0 {
		t.Fatalf("changed ciphertext auto-decrypted without acceptance:\n%s", out)
	}
	for _, keyName := range []string{"DATABASE_URL", "NEW_KEY"} {
		if !strings.Contains(out, keyName) {
			t.Errorf("blocked message missing key name %q:\n%s", keyName, out)
		}
	}
	for _, secret := range []string{secretValue, "hidden-value", "sentinel"} {
		if strings.Contains(out, secret) {
			t.Fatalf("blocked message leaked secret %q:\n%s", secret, out)
		}
	}
	got, _ := os.ReadFile(filepath.Join(fixture.repo, ".env"))
	if string(got) != "DATABASE_URL=sentinel\n" {
		t.Fatalf("blocked hook modified plaintext: %q", got)
	}

	if out, code := run(t, fixture.repo, fixture.bin, "decrypt", "--identity", fixture.identity, "--accept-changes"); code != 0 {
		t.Fatalf("accept changes: %d\n%s", code, out)
	}
	got, _ = os.ReadFile(filepath.Join(fixture.repo, ".env"))
	if string(got) != "DATABASE_URL="+secretValue+"\nNEW_KEY=hidden-value\n" {
		t.Fatal("accepted decrypt did not install the committed dotenv")
	}
	state, err := loadAutoDecryptState(filepath.Join(fixture.repo, config.AutoDecryptStateRelative))
	if err != nil {
		t.Fatal(err)
	}
	if state.Commit != strings.TrimSpace(current) {
		t.Fatalf("state commit = %q, want %q", state.Commit, strings.TrimSpace(current))
	}
}

func TestRecipientChangeReportsNamesAndDoesNotWrite(t *testing.T) {
	fixture := setupTrustedRepo(t, "SAFE=original\n")
	if out, code := run(t, fixture.repo, "git", "checkout", "-b", "changed-recipients"); code != 0 {
		t.Fatalf("create branch: %d\n%s", code, out)
	}
	bobKey := writeAgeID(t, filepath.Join(fixture.repo, "bob-id.txt"))
	if out, code := run(t, fixture.repo, fixture.bin, "add-recipient", "--identity", fixture.identity, "--key", bobKey, "--name", "bob"); code != 0 {
		t.Fatalf("add recipient: %d\n%s", code, out)
	}
	if out, code := run(t, fixture.repo, "git", "add", ".envguardian/recipients.toml", ".envguardian/lock.toml", ".env.age"); code != 0 {
		t.Fatalf("stage recipient change: %d\n%s", code, out)
	}
	if out, code := run(t, fixture.repo, "git", "commit", "-m", "add bob"); code != 0 {
		t.Fatalf("commit recipient change: %d\n%s", code, out)
	}
	if err := os.WriteFile(filepath.Join(fixture.repo, ".env"), []byte("SAFE=sentinel\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, code := run(t, fixture.repo, fixture.bin, "hook-auto-decrypt", "--identity", fixture.identity)
	if code == 0 {
		t.Fatalf("recipient change auto-decrypted without acceptance:\n%s", out)
	}
	if !strings.Contains(out, "recipient added: bob") {
		t.Fatalf("recipient name was not reported:\n%s", out)
	}
	got, _ := os.ReadFile(filepath.Join(fixture.repo, ".env"))
	if string(got) != "SAFE=sentinel\n" {
		t.Fatalf("blocked recipient change modified plaintext: %q", got)
	}
}
