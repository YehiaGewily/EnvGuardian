package cli

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type repoSnapshot struct {
	recipients []byte
	ciphertext []byte
	signature  []byte
	lock       []byte
}

func snapshotRecipientTransaction(t *testing.T, dir string) repoSnapshot {
	t.Helper()
	read := func(path string) []byte {
		data, err := os.ReadFile(filepath.Join(dir, path))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	return repoSnapshot{
		recipients: read(".envguardian/recipients.toml"),
		ciphertext: read(".env.age"),
		signature:  read(".env.age.sig"),
		lock:       read(".envguardian/lock.toml"),
	}
}

func (want repoSnapshot) assertUnchanged(t *testing.T, dir string) {
	t.Helper()
	got := snapshotRecipientTransaction(t, dir)
	if !bytes.Equal(want.recipients, got.recipients) || !bytes.Equal(want.ciphertext, got.ciphertext) || !bytes.Equal(want.signature, got.signature) || !bytes.Equal(want.lock, got.lock) {
		t.Fatal("failed recipient operation modified recipients, ciphertext, signature, or lock")
	}
}

func TestAddRecipientWithoutLocalPlaintextUsesCiphertextInMemory(t *testing.T) {
	pinDate(t)
	dir := t.TempDir()
	t.Chdir(dir)
	aliceID := setupRepo(t, dir, "A=committed\n")
	bobID := filepath.Join(dir, "bob.txt")
	bobKey := writeAgeID(t, bobID)
	if err := os.Remove(filepath.Join(dir, ".env")); err != nil {
		t.Fatal(err)
	}

	out, stderr, code := runCLI(t, "add-recipient", "--identity", aliceID, "--key", bobKey, "--name", "bob")
	if code != exitOK {
		t.Fatalf("add-recipient exit=%d\nstdout=%s\nstderr=%s", code, out, stderr)
	}
	if _, err := os.Stat(filepath.Join(dir, ".env")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("recipient operation wrote missing plaintext to disk: %v", err)
	}
	if _, _, code := runCLI(t, "decrypt", "--identity", bobID); code != exitOK {
		t.Fatalf("new recipient cannot decrypt, exit=%d", code)
	}
	if got, err := os.ReadFile(filepath.Join(dir, ".env")); err != nil || string(got) != "A=committed\n" {
		t.Fatalf("decrypted content = %q, %v", got, err)
	}
}

func TestAddRecipientRejectsStalePlaintextWithoutMutation(t *testing.T) {
	pinDate(t)
	dir := t.TempDir()
	t.Chdir(dir)
	aliceID := setupRepo(t, dir, "A=committed\n")
	before := snapshotRecipientTransaction(t, dir)
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("A=stale-branch\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bobKey := writeAgeID(t, filepath.Join(dir, "bob.txt"))

	_, stderr, code := runCLI(t, "add-recipient", "--identity", aliceID, "--key", bobKey, "--name", "bob")
	if code != exitOutOfSync || !strings.Contains(stderr, "differs from its decrypted content") {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	before.assertUnchanged(t, dir)
}

func TestAddRecipientEnforcesGitignoreBeforeMutation(t *testing.T) {
	pinDate(t)
	dir := t.TempDir()
	t.Chdir(dir)
	aliceID := setupRepo(t, dir, "A=1\n")
	before := snapshotRecipientTransaction(t, dir)
	if err := os.WriteFile(filepath.Join(dir, ".gitignore"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	bobKey := writeAgeID(t, filepath.Join(dir, "bob.txt"))

	_, stderr, code := runCLI(t, "add-recipient", "--identity", aliceID, "--key", bobKey, "--name", "bob")
	if code != exitConfig || !strings.Contains(stderr, "not ignored") {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	before.assertUnchanged(t, dir)
}

func TestAddRecipientUndecryptableAndInvalidIdentityModifyNothing(t *testing.T) {
	tests := []struct {
		name       string
		identityFn func(*testing.T, string) string
	}{
		{name: "wrong identity", identityFn: func(t *testing.T, dir string) string {
			path := filepath.Join(dir, "wrong.txt")
			writeAgeID(t, path)
			return path
		}},
		{name: "invalid explicit identity", identityFn: func(t *testing.T, dir string) string {
			path := filepath.Join(dir, "invalid.txt")
			if err := os.WriteFile(path, []byte("not-an-identity\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			return path
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pinDate(t)
			dir := t.TempDir()
			t.Chdir(dir)
			setupRepo(t, dir, "A=1\n")
			before := snapshotRecipientTransaction(t, dir)
			bobKey := writeAgeID(t, filepath.Join(dir, "bob.txt"))
			identity := tt.identityFn(t, dir)
			_, _, code := runCLI(t, "add-recipient", "--identity", identity, "--key", bobKey, "--name", "bob")
			if code != exitIdentity {
				t.Fatalf("exit=%d, want %d", code, exitIdentity)
			}
			before.assertUnchanged(t, dir)
		})
	}
}

func TestGlobalJSONContractAndVerboseOutput(t *testing.T) {
	_, stderr, code := runCLI(t, "version", "--json")
	if code != exitConfig || !strings.Contains(stderr, "only with check or list-recipients") {
		t.Fatalf("unsupported --json exit=%d stderr=%s", code, stderr)
	}
	_, stderr, code = runCLI(t, "version", "--verbose")
	if code != exitOK || !strings.Contains(stderr, "verbose: command=version") {
		t.Fatalf("verbose exit=%d stderr=%s", code, stderr)
	}
}

func TestListRecipientsJSONUsesStableFieldNames(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	idPath := filepath.Join(dir, "id.txt")
	writeAgeID(t, idPath)
	if _, _, code := runCLI(t, "init", "--identity", idPath, "--name", "alice"); code != exitOK {
		t.Fatal("init failed")
	}
	out, _, code := runCLI(t, "list-recipients", "--json")
	if code != exitOK || !strings.Contains(out, `"name": "alice"`) || strings.Contains(out, `"Name"`) {
		t.Fatalf("list JSON exit=%d output=%s", code, out)
	}
}

func TestMalformedDotenvAndConfigUseExitCodeThree(t *testing.T) {
	pinDate(t)
	dir := t.TempDir()
	t.Chdir(dir)
	idPath := filepath.Join(dir, "id.txt")
	writeAgeID(t, idPath)
	if _, _, code := runCLI(t, "init", "--identity", idPath, "--name", "alice"); code != exitOK {
		t.Fatal("init failed")
	}
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("not dotenv\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, code := runCLI(t, "encrypt", "--identity", idPath); code != exitConfig {
		t.Fatalf("invalid dotenv exit=%d, want %d", code, exitConfig)
	}
	configPath := filepath.Join(dir, ".envguardian", "config.toml")
	if err := os.WriteFile(configPath, []byte("version = 1\nunknown = true\n[[file]]\nplaintext = \".env\"\nciphertext = \".env.age\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, code := runCLI(t, "check"); code != exitConfig {
		t.Fatalf("check invalid config exit=%d, want %d", code, exitConfig)
	}
	if _, _, code := runCLI(t, "encrypt", "--identity", idPath); code != exitConfig {
		t.Fatalf("command invalid config exit=%d, want %d", code, exitConfig)
	}
}

func TestPreCommitWithoutConfigDoesNothing(t *testing.T) {
	dir := gitInitRepo(t)
	t.Chdir(dir)
	if err := runHookPreCommit(&globalFlags{}, io.Discard); err != nil {
		t.Fatalf("pre-commit without config = %v, want nil", err)
	}
}

func TestPreCommitGitFailureFailsClosed(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := runHookPreCommit(&globalFlags{}, io.Discard); err == nil {
		t.Fatal("pre-commit outside a Git repository succeeded; want fail-closed error")
	}
}

func TestCheckRejectsInvalidExplicitIdentity(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	setupRepo(t, dir, "A=1\n")
	invalid := filepath.Join(dir, "invalid.txt")
	if err := os.WriteFile(invalid, []byte("not-an-identity\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, stderr, code := runCLI(t, "check", "--identity", invalid); code != exitIdentity {
		t.Fatalf("check invalid identity exit=%d, want %d; stderr=%s", code, exitIdentity, stderr)
	}
}

func TestCommandsRunFromRepositorySubdirectory(t *testing.T) {
	repo := gitInitRepo(t)
	bin := buildBinary(t)
	nested := filepath.Join(repo, "nested", "deeper")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	idPath := filepath.Join(repo, "id.txt")
	writeAgeID(t, idPath)
	if out, code := run(t, nested, bin, "init", "--identity", idPath, "--name", "alice"); code != exitOK {
		t.Fatalf("subdirectory init: %d\n%s", code, out)
	}
	if _, err := os.Stat(filepath.Join(repo, ".envguardian", "config.toml")); err != nil {
		t.Fatalf("config not created at repository root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(nested, ".envguardian")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("subdirectory received its own config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".env"), []byte("A=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, code := run(t, nested, bin, "encrypt", "--identity", idPath); code != exitOK {
		t.Fatalf("subdirectory encrypt: %d\n%s", code, out)
	}
	if _, err := os.Stat(filepath.Join(repo, ".env.age")); err != nil {
		t.Fatalf("ciphertext not created at repository root: %v", err)
	}
}

func TestCustomConfigUsesIndependentLock(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, ".envguardian", "staging.toml")
	p := rootPaths(&globalFlags{config: configPath})
	want := filepath.Join(root, ".envguardian", "staging.lock.toml")
	if p.Lock != want {
		t.Fatalf("custom config lock = %q, want %q", p.Lock, want)
	}
	defaultPaths := rootPaths(&globalFlags{config: filepath.Join(root, ".envguardian", "config.toml")})
	if defaultPaths.Lock != filepath.Join(root, ".envguardian", "lock.toml") {
		t.Fatalf("default config lock = %q", defaultPaths.Lock)
	}
}

func TestHookBodyPreservesExplicitConfig(t *testing.T) {
	body := hookBody("post-merge", "envguardian", "C:/repo/.envguardian/staging.toml")
	if !strings.Contains(body, `--config "C:/repo/.envguardian/staging.toml" hook-auto-decrypt`) {
		t.Fatalf("custom-config hook body = %q", body)
	}
}

func TestSecureRootPathsRejectsSymlinkedMetadataDirectory(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, ".envguardian")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	t.Chdir(root)
	if _, err := secureRootPaths(&globalFlags{}); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("secureRootPaths error = %v, want symlink escape rejection", err)
	}
}

func TestSingleGitHubKeySelectionFailsOnMultiple(t *testing.T) {
	_, err := selectSingleGitHubKey("alice", []string{"key-one", "key-two"})
	if err == nil || !strings.Contains(err.Error(), "2 ssh-ed25519 keys") {
		t.Fatalf("error = %v", err)
	}
}
