package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/YehiaGewily/envguardian/internal/config"
	"github.com/YehiaGewily/envguardian/internal/keys"
	"github.com/YehiaGewily/envguardian/internal/rotation"
)

func prepareRevocationRepo(t *testing.T) (repo, aliceIdentity string) {
	t.Helper()
	repo = t.TempDir()
	if out, code := run(t, repo, "git", "init"); code != exitOK {
		t.Fatalf("git init: %s", out)
	}
	if out, code := run(t, repo, "git", "config", "user.email", "test@example.com"); code != exitOK {
		t.Fatalf("git config email: %s", out)
	}
	if out, code := run(t, repo, "git", "config", "user.name", "Test User"); code != exitOK {
		t.Fatalf("git config name: %s", out)
	}
	aliceIdentity = filepath.Join(repo, "alice-id")
	writeAgeID(t, aliceIdentity)
	if out, errOut, code := runCLIInDir(t, repo, "init", "--identity", aliceIdentity, "--name", "alice"); code != exitOK {
		t.Fatalf("init: %d\n%s%s", code, out, errOut)
	}
	if err := os.WriteFile(filepath.Join(repo, ".env"), []byte("DATABASE_URL=local\nTOKEN=local\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, errOut, code := runCLIInDir(t, repo, "encrypt", "--identity", aliceIdentity); code != exitOK {
		t.Fatalf("encrypt: %d\n%s%s", code, out, errOut)
	}
	bobIdentity := filepath.Join(repo, "bob-id")
	bobKey := writeAgeID(t, bobIdentity)
	if out, errOut, code := runCLIInDir(t, repo, "add-recipient", "--identity", aliceIdentity, "--name", "bob", "--key", bobKey); code != exitOK {
		t.Fatalf("add bob: %d\n%s%s", code, out, errOut)
	}
	return repo, aliceIdentity
}

func TestRevokeCreatesKeyNameOnlyLedgerAndRotationCommands(t *testing.T) {
	repo, aliceIdentity := prepareRevocationRepo(t)
	out, stderr, code := runCLIInDir(t, repo, "revoke", "bob", "--identity", aliceIdentity)
	if code != exitOK {
		t.Fatalf("revoke: %d\n%s%s", code, out, stderr)
	}
	if !strings.Contains(out, "cannot revoke secrets already present in git history") {
		t.Fatalf("revoke output lacks history warning: %s", out)
	}

	paths := config.PathsFor(repo)
	recipients, err := keys.LoadRecipients(paths.Recipients)
	if err != nil {
		t.Fatal(err)
	}
	if got := recipients.Names(); !reflect.DeepEqual(got, []string{"alice"}) {
		t.Fatalf("recipients after revoke = %v", got)
	}
	ledger, err := rotation.Load(paths.Rotation)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := ledger.Keys(), []string{"DATABASE_URL", "TOKEN"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("pending keys = %v, want %v", got, want)
	}
	ledgerBytes, err := os.ReadFile(paths.Rotation)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(ledgerBytes), "=local") {
		t.Fatal("rotation ledger exposed a plaintext value")
	}

	out, stderr, code = runCLIInDir(t, repo, "rotation", "status", "--json")
	if code != exitOK {
		t.Fatalf("rotation status: %d %s", code, stderr)
	}
	var status struct {
		Pending []string `json:"pending"`
	}
	if err := json.Unmarshal([]byte(out), &status); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(status.Pending, []string{"DATABASE_URL", "TOKEN"}) {
		t.Fatalf("JSON pending = %v", status.Pending)
	}

	out, stderr, code = runCLIInDir(t, repo, "rotation", "done", "TOKEN", "--json")
	if code != exitOK || strings.Contains(out+stderr, "local") {
		t.Fatalf("rotation done: code=%d out=%s err=%s", code, out, stderr)
	}
	ledger, err = rotation.Load(paths.Rotation)
	if err != nil || !reflect.DeepEqual(ledger.Keys(), []string{"DATABASE_URL"}) {
		t.Fatalf("remaining ledger = %+v, %v", ledger, err)
	}
	if _, _, code := runCLIInDir(t, repo, "revoke", "alice", "--identity", aliceIdentity); code != exitConfig {
		t.Fatalf("revoking last recipient exit = %d, want %d", code, exitConfig)
	}
}

func TestRevokeDivergenceModifiesNothing(t *testing.T) {
	repo, aliceIdentity := prepareRevocationRepo(t)
	paths := config.PathsFor(repo)
	beforeRecipients, _ := os.ReadFile(paths.Recipients)
	beforeCiphertext, _ := os.ReadFile(filepath.Join(repo, ".env.age"))
	beforeLock, _ := os.ReadFile(paths.Lock)
	if err := os.WriteFile(filepath.Join(repo, ".env"), []byte("DATABASE_URL=stale\nTOKEN=local\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, code := runCLIInDir(t, repo, "revoke", "bob", "--identity", aliceIdentity)
	if code == exitOK {
		t.Fatal("revoke accepted divergent local plaintext")
	}
	afterRecipients, _ := os.ReadFile(paths.Recipients)
	afterCiphertext, _ := os.ReadFile(filepath.Join(repo, ".env.age"))
	afterLock, _ := os.ReadFile(paths.Lock)
	if !reflect.DeepEqual(beforeRecipients, afterRecipients) || !reflect.DeepEqual(beforeCiphertext, afterCiphertext) || !reflect.DeepEqual(beforeLock, afterLock) {
		t.Fatal("failed revoke modified recipients, ciphertext, or lock")
	}
	if _, err := os.Stat(paths.Rotation); !os.IsNotExist(err) {
		t.Fatalf("failed revoke wrote rotation ledger: %v", err)
	}
}

func TestRotationCommandsFailOnMalformedLedger(t *testing.T) {
	repo := t.TempDir()
	if out, code := run(t, repo, "git", "init"); code != exitOK {
		t.Fatalf("git init: %s", out)
	}
	paths := config.PathsFor(repo)
	if err := os.MkdirAll(paths.Dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.Rotation, []byte("version = ["), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, code := runCLIInDir(t, repo, "rotation", "status"); code != exitConfig {
		t.Fatalf("malformed rotation status exit = %d", code)
	}
	if _, _, code := runCLIInDir(t, repo, "rotation", "done", "TOKEN"); code != exitConfig {
		t.Fatalf("malformed rotation done exit = %d", code)
	}
}
