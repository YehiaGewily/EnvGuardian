package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestShellWordRoundTripsShellQuote(t *testing.T) {
	for _, value := range []string{"/usr/local/bin/envguardian", "C:/Program Files/eg/envguardian.exe", "/tmp/it's $HOME `id`"} {
		word, rest, ok := shellWord(shellQuote(value) + " diff-driver")
		if !ok || word != value || strings.TrimSpace(rest) != "diff-driver" {
			t.Errorf("shellWord(shellQuote(%q)) = %q, %q, %v", value, word, rest, ok)
		}
	}
	for _, bad := range []string{"", "'unterminated", "/bin/$HOME", `a\b`} {
		if _, _, ok := shellWord(bad); ok {
			t.Errorf("shellWord(%q) accepted", bad)
		}
	}
}

func TestDoctorReportsSetupProblemsWithoutValues(t *testing.T) {
	repo, identity := setupCommittedHookRepo(t)
	if err := os.WriteFile(filepath.Join(repo, ".env"), []byte("A=sentinel-doctor-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	out, code := runCLICombinedInDir(t, repo, "doctor")
	if code != exitOK || !strings.Contains(out, "[SKIP] hook pre-commit") || !strings.Contains(out, "[WARN] trust state") {
		t.Fatalf("fresh repository doctor exit=%d\n%s", code, out)
	}

	if out, code := runCLICombinedInDir(t, repo, "install-hooks"); code != exitOK {
		t.Fatalf("install-hooks: %d\n%s", code, out)
	}
	if out, code := runCLICombinedInDir(t, repo, "decrypt", "--accept-changes", "--identity", identity); code != exitOK {
		t.Fatalf("accept: %d\n%s", code, out)
	}
	out, code = runCLICombinedInDir(t, repo, "doctor", "--json")
	if code != exitOK || !strings.Contains(out, "HEAD matches accepted commit") || !strings.Contains(out, `"ok": true`) {
		t.Fatalf("healthy doctor exit=%d\n%s", code, out)
	}

	hook := filepath.Join(repo, ".git", "hooks", "pre-commit")
	data, err := os.ReadFile(hook)
	if err != nil {
		t.Fatal(err)
	}
	moved := strings.Replace(string(data), "envguardian_bin='", "envguardian_bin='/nonexistent/moved", 1)
	if err := os.WriteFile(hook, []byte(moved), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(repo, ".gitattributes")); err != nil {
		t.Fatal(err)
	}
	out, code = runCLICombinedInDir(t, repo, "doctor")
	if code == exitOK {
		t.Fatalf("doctor passed with a moved binary and missing attributes:\n%s", out)
	}
	for _, want := range []string{"[FAIL] hook pre-commit", "is missing", "[FAIL] attributes .env.age", "*.age -text"} {
		if !strings.Contains(out, want) {
			t.Fatalf("doctor output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "sentinel-doctor-value") {
		t.Fatalf("doctor printed a plaintext value:\n%s", out)
	}
}

func TestAddFileAndRemoveFileAreTransactional(t *testing.T) {
	repo, identity := setupCommittedHookRepo(t)
	configPath := filepath.Join(repo, ".envguardian", "config.toml")
	if err := os.MkdirAll(filepath.Join(repo, "config"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "config", "dev.env"), []byte("B=sentinel-add-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}

	outsider := filepath.Join(t.TempDir(), "outsider")
	writeAgeID(t, outsider)
	out, code := runCLICombinedInDir(t, repo, "add-file", "config/dev.env", "--identity", identity, "--signing-key", outsider+".pub")
	if code != exitSignature {
		t.Fatalf("add-file with a non-recipient signer exit=%d\n%s", code, out)
	}
	if after, _ := os.ReadFile(configPath); !bytes.Equal(before, after) {
		t.Fatal("config changed although the add-file transaction failed")
	}
	if _, err := os.Stat(filepath.Join(repo, "config", "dev.env.age")); !os.IsNotExist(err) {
		t.Fatalf("ciphertext written although the transaction failed: %v", err)
	}

	for _, tt := range []struct {
		args []string
		want string
	}{
		{[]string{"add-file", ".env"}, "already managed"},
		{[]string{"add-file", "missing.env"}, "does not exist"},
		{[]string{"add-file", "../outside.env"}, "invalid managed file mapping"},
		{[]string{"add-file", "config/dev.env", "--ciphertext", "config/dev.enc"}, "must end in .age"},
	} {
		out, code := runCLICombinedInDir(t, repo, append(tt.args, "--identity", identity)...)
		if code != exitConfig || !strings.Contains(out, tt.want) {
			t.Fatalf("%v exit=%d, want %d with %q\n%s", tt.args, code, exitConfig, tt.want, out)
		}
	}

	out, code = runCLICombinedInDir(t, repo, "add-file", "config/dev.env", "--identity", identity)
	if code != exitOK || !strings.Contains(out, "now managing config/dev.env") {
		t.Fatalf("add-file exit=%d\n%s", code, out)
	}
	for _, name := range []string{"config/dev.env.age", "config/dev.env.age.sig"} {
		if _, err := os.Stat(filepath.Join(repo, filepath.FromSlash(name))); err != nil {
			t.Fatalf("%s missing after add-file: %v", name, err)
		}
	}
	if out, code := runCLICombinedInDir(t, repo, "check", "--identity", identity); code != exitOK || !strings.Contains(out, "config/dev.env.age") {
		t.Fatalf("check after add-file exit=%d\n%s", code, out)
	}
	if strings.Contains(out, "sentinel-add-file") {
		t.Fatalf("add-file printed a plaintext value:\n%s", out)
	}

	if out, code := runCLICombinedInDir(t, repo, "remove-file", "unknown.env", "--identity", identity); code != exitConfig || !strings.Contains(out, "is not managed") {
		t.Fatalf("remove unknown exit=%d\n%s", code, out)
	}
	out, code = runCLICombinedInDir(t, repo, "remove-file", "config/dev.env", "--identity", identity)
	if code != exitOK || !strings.Contains(out, "git rm config/dev.env.age config/dev.env.age.sig") {
		t.Fatalf("remove-file exit=%d\n%s", code, out)
	}
	if out, code := runCLICombinedInDir(t, repo, "check", "--identity", identity); code != exitOK || strings.Contains(out, "config/dev.env.age") {
		t.Fatalf("check after remove-file exit=%d\n%s", code, out)
	}
	if out, code := runCLICombinedInDir(t, repo, "remove-file", ".env", "--identity", identity); code != exitConfig || !strings.Contains(out, "only managed file") {
		t.Fatalf("removing the last mapping exit=%d\n%s", code, out)
	}
}
