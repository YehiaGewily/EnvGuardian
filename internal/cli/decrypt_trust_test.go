package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Sentinel plaintext values. Neither may appear in any output stream.
const (
	aliceSecret    = "alice-sentinel-7f3a91c2"
	attackerSecret = "mallory-sentinel-0be44d18"
)

type hostileBranchRepo struct {
	repo, bin            string
	aliceID, malloryID   string
	mainBranch, branch   string
	alicePlaintext       []byte
	aliceEnv, malloryEnv []string
	attackerPlaintext    []byte
}

// setupHostileBranch builds the reproduced finding: Alice seals and accepts a
// baseline, then Mallory, who can push branches but is not a recipient, adds
// her own key to recipients.toml on a branch, writes attacker values, and runs
// `encrypt --force`, producing a signature that verifies against her branch's
// recipients. Alice is back on main with her own plaintext; hooks are not yet
// installed.
func setupHostileBranch(t *testing.T) hostileBranchRepo {
	t.Helper()
	repo := gitInitRepo(t)
	bin := buildBinary(t)
	keysDir := t.TempDir()
	aliceID := filepath.Join(keysDir, "alice")
	malloryID := filepath.Join(keysDir, "mallory")
	writeAgeID(t, aliceID)
	malloryKey := writeAgeID(t, malloryID)
	fx := hostileBranchRepo{
		repo: repo, bin: bin, aliceID: aliceID, malloryID: malloryID, branch: "mallory",
		alicePlaintext:    []byte("API_TOKEN=" + aliceSecret + "\nDB_HOST=localhost\n"),
		attackerPlaintext: []byte("API_TOKEN=" + attackerSecret + "\nDB_HOST=attacker.invalid\nEXFIL_URL=https://attacker.invalid\n"),
		aliceEnv:          append(os.Environ(), "ENVGUARDIAN_IDENTITY="+aliceID),
		malloryEnv:        append(os.Environ(), "ENVGUARDIAN_IDENTITY="+malloryID),
	}
	gitAs := func(env []string, args ...string) {
		t.Helper()
		if out, code := runEnv(t, repo, env, "git", args...); code != 0 {
			t.Fatalf("git %v: %d\n%s", args, code, out)
		}
	}

	if out, code := runCLICombinedInDir(t, repo, "init", "--identity", aliceID, "--name", "alice"); code != exitOK {
		t.Fatalf("alice init: %d\n%s", code, out)
	}
	fx.writePlaintext(t, fx.alicePlaintext)
	if out, code := runCLICombinedInDir(t, repo, "encrypt", "--identity", aliceID); code != exitOK {
		t.Fatalf("alice encrypt: %d\n%s", code, out)
	}
	gitAs(fx.aliceEnv, "add", ".envguardian", ".env.age", ".env.age.sig", ".gitignore", ".gitattributes")
	gitAs(fx.aliceEnv, "commit", "-q", "-m", "alice baseline")
	if out, code := runCLICombinedInDir(t, repo, "decrypt", "--accept-changes", "--identity", aliceID); code != exitOK {
		t.Fatalf("alice accepts baseline: %d\n%s", code, out)
	}
	mainBranch, _ := run(t, repo, "git", "branch", "--show-current")
	fx.mainBranch = strings.TrimSpace(mainBranch)

	gitAs(fx.malloryEnv, "checkout", "-q", "-b", fx.branch)
	recipientsPath := filepath.Join(repo, ".envguardian", "recipients.toml")
	recipients, err := os.ReadFile(recipientsPath)
	if err != nil {
		t.Fatal(err)
	}
	recipients = append(recipients, fmt.Sprintf("\n[[recipient]]\nname = \"mallory\"\nkey = %q\nsource = \"manual\"\nadded_at = \"2026-10-08\"\nadded_by = \"mallory\"\n", malloryKey)...)
	if err := os.WriteFile(recipientsPath, recipients, 0o644); err != nil {
		t.Fatal(err)
	}
	fx.writePlaintext(t, fx.attackerPlaintext)
	if out, code := runCLICombinedInDir(t, repo, "encrypt", "--force", "--identity", malloryID); code != exitOK {
		t.Fatalf("mallory encrypt --force: %d\n%s", code, out)
	}
	gitAs(fx.malloryEnv, "add", ".envguardian", ".env.age", ".env.age.sig")
	gitAs(fx.malloryEnv, "commit", "-q", "-m", "routine config update")
	if out, code := runCLICombinedInDir(t, repo, "check", "--identity", malloryID); code != exitOK {
		t.Fatalf("mallory's branch should pass check against its own recipients: %d\n%s", code, out)
	}

	gitAs(fx.aliceEnv, "checkout", "-q", fx.mainBranch)
	fx.writePlaintext(t, fx.alicePlaintext)
	return fx
}

func (fx hostileBranchRepo) writePlaintext(t *testing.T, content []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(fx.repo, ".env"), content, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (fx hostileBranchRepo) assertAlicePlaintextUnchanged(t *testing.T, step string) {
	t.Helper()
	got, err := os.ReadFile(filepath.Join(fx.repo, ".env"))
	if err != nil {
		t.Fatalf("%s: read .env: %v", step, err)
	}
	if !bytes.Equal(got, fx.alicePlaintext) {
		t.Fatalf("%s modified Alice's .env", step)
	}
}

func assertNoSentinels(t *testing.T, step, output string) {
	t.Helper()
	for _, sentinel := range []string{aliceSecret, attackerSecret} {
		if strings.Contains(output, sentinel) {
			t.Fatalf("%s exposed a sentinel secret value in its output", step)
		}
	}
}

func TestPlainDecryptRefusesSelfAddedRecipientBranch(t *testing.T) {
	fx := setupHostileBranch(t)
	if out, code := run(t, fx.repo, fx.bin, "install-hooks"); code != exitOK {
		t.Fatalf("install hooks: %d\n%s", code, out)
	}

	checkoutOut, code := runEnv(t, fx.repo, fx.aliceEnv, "git", "checkout", fx.branch)
	assertNoSentinels(t, "post-checkout hook", checkoutOut)
	if code == 0 || !strings.Contains(checkoutOut, "automatic decryption blocked") || !strings.Contains(checkoutOut, "recipient added: mallory") {
		t.Fatalf("post-checkout hook did not block Mallory's branch: %d\n%s", code, checkoutOut)
	}
	fx.assertAlicePlaintextUnchanged(t, "blocked checkout")

	stdout, stderr, code := runCLIInDir(t, fx.repo, "decrypt", "--identity", fx.aliceID)
	assertNoSentinels(t, "plain decrypt", stdout+stderr)
	if code != exitOutOfSync {
		t.Fatalf("plain decrypt of Mallory's branch exit = %d, want %d\n%s%s", code, exitOutOfSync, stdout, stderr)
	}
	for _, want := range []string{
		"decryption blocked", "recipient added: mallory", "+ EXFIL_URL", "~ API_TOKEN", "~ DB_HOST",
		"ciphertext signature .env.age.sig changed", "decrypt --accept-changes",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("plain decrypt report missing %q:\n%s", want, stderr)
		}
	}
	if stdout != "" {
		t.Errorf("refused decrypt wrote to stdout: %q", stdout)
	}
	fx.assertAlicePlaintextUnchanged(t, "refused plain decrypt")

	// A merge that fast-forwards to Mallory's branch is held by post-merge too.
	if out, code := runEnv(t, fx.repo, fx.aliceEnv, "git", "checkout", "-q", fx.mainBranch); code != 0 {
		assertNoSentinels(t, "return to main", out)
		t.Fatalf("return to main: %d\n%s", code, out)
	}
	fx.assertAlicePlaintextUnchanged(t, "return to main")
	mergeOut, code := runEnv(t, fx.repo, fx.aliceEnv, "git", "merge", "--ff-only", fx.branch)
	assertNoSentinels(t, "post-merge hook", mergeOut)
	// Git ignores post-merge's exit status, so the merge itself succeeds; the
	// hook's report is what shows it refused to write.
	if code != 0 || !strings.Contains(mergeOut, "automatic decryption blocked") || !strings.Contains(mergeOut, "recipient added: mallory") {
		t.Fatalf("post-merge hook did not block Mallory's branch: %d\n%s", code, mergeOut)
	}
	fx.assertAlicePlaintextUnchanged(t, "blocked post-merge hook")
	stdout, stderr, code = runCLIInDir(t, fx.repo, "decrypt", "--identity", fx.aliceID)
	assertNoSentinels(t, "plain decrypt after merge", stdout+stderr)
	if code != exitOutOfSync {
		t.Fatalf("plain decrypt after merge exit = %d, want %d\n%s%s", code, exitOutOfSync, stdout, stderr)
	}
	fx.assertAlicePlaintextUnchanged(t, "plain decrypt after merge")

	// Explicit acceptance is the only transition, and it is deliberate.
	stdout, stderr, code = runCLIInDir(t, fx.repo, "decrypt", "--accept-changes", "--identity", fx.aliceID)
	assertNoSentinels(t, "decrypt --accept-changes", stdout+stderr)
	if code != exitOK {
		t.Fatalf("decrypt --accept-changes exit = %d\n%s%s", code, stdout, stderr)
	}
	got, err := os.ReadFile(filepath.Join(fx.repo, ".env"))
	if err != nil || !bytes.Equal(got, fx.attackerPlaintext) {
		t.Fatalf("accepted decrypt did not install the accepted commit's plaintext: %v", err)
	}
	stdout, stderr, code = runCLIInDir(t, fx.repo, "decrypt", "--identity", fx.aliceID)
	assertNoSentinels(t, "plain decrypt after acceptance", stdout+stderr)
	if code != exitOK {
		t.Fatalf("plain decrypt after acceptance exit = %d\n%s%s", code, stdout, stderr)
	}
}

func TestPlainDecryptRefusesUncommittedHostileFiles(t *testing.T) {
	fx := setupHostileBranch(t)

	// Recipients and ciphertext copied from Mallory's branch into Alice's work
	// tree and index without a commit: HEAD still equals the accepted commit.
	if out, code := run(t, fx.repo, "git", "checkout", fx.branch, "--", ".envguardian/recipients.toml", ".env.age", ".env.age.sig"); code != 0 {
		t.Fatalf("copy hostile files: %d\n%s", code, out)
	}
	stdout, stderr, code := runCLIInDir(t, fx.repo, "decrypt", "--identity", fx.aliceID)
	assertNoSentinels(t, "decrypt with uncommitted hostile recipients", stdout+stderr)
	if code != exitOutOfSync || !strings.Contains(stderr, ".envguardian/recipients.toml has uncommitted changes") || !strings.Contains(stderr, "--accept-changes") {
		t.Fatalf("uncommitted hostile recipients exit = %d, want %d\n%s%s", code, exitOutOfSync, stdout, stderr)
	}
	fx.assertAlicePlaintextUnchanged(t, "decrypt with uncommitted hostile recipients")

	// Without the recipients change, Mallory's signature is not by a recipient
	// of the accepted snapshot, so the uncommitted ciphertext fails closed.
	if out, code := run(t, fx.repo, "git", "checkout", "HEAD", "--", ".envguardian/recipients.toml"); code != 0 {
		t.Fatalf("restore recipients: %d\n%s", code, out)
	}
	stdout, stderr, code = runCLIInDir(t, fx.repo, "decrypt", "--identity", fx.aliceID)
	assertNoSentinels(t, "decrypt with uncommitted hostile ciphertext", stdout+stderr)
	if code != exitSignature {
		t.Fatalf("uncommitted hostile ciphertext exit = %d, want %d\n%s%s", code, exitSignature, stdout, stderr)
	}
	fx.assertAlicePlaintextUnchanged(t, "decrypt with uncommitted hostile ciphertext")
}

func TestPlainDecryptWithAcceptedStateRestoresPlaintext(t *testing.T) {
	fixture := setupTrustedRepo(t, "A="+aliceSecret+"\n")
	if err := os.Remove(filepath.Join(fixture.repo, ".env")); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code := runCLIInDir(t, fixture.repo, "decrypt", "--identity", fixture.identity)
	assertNoSentinels(t, "plain decrypt", stdout+stderr)
	if code != exitOK || stdout != "decrypted .env.age → .env\n" {
		t.Fatalf("unchanged trusted decrypt exit = %d\n%s%s", code, stdout, stderr)
	}
	got, err := os.ReadFile(filepath.Join(fixture.repo, ".env"))
	if err != nil || string(got) != "A="+aliceSecret+"\n" {
		t.Fatalf("plaintext not restored: %v", err)
	}
}

// Decision (a): with no recorded trust state, e.g. a fresh clone, the first
// trust decision must be explicit.
func TestPlainDecryptWithoutTrustStateRequiresAcceptance(t *testing.T) {
	repo := gitInitRepo(t)
	identity := filepath.Join(t.TempDir(), "id")
	writeAgeID(t, identity)
	if out, code := runCLICombinedInDir(t, repo, "init", "--identity", identity, "--name", "alice"); code != exitOK {
		t.Fatalf("init: %d\n%s", code, out)
	}
	if err := os.WriteFile(filepath.Join(repo, ".env"), []byte("A="+aliceSecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, code := runCLICombinedInDir(t, repo, "encrypt", "--identity", identity); code != exitOK {
		t.Fatalf("encrypt: %d\n%s", code, out)
	}
	for _, args := range [][]string{{"add", "-A"}, {"commit", "-q", "-m", "seal"}} {
		if out, code := run(t, repo, "git", args...); code != 0 {
			t.Fatalf("git %v: %d\n%s", args, code, out)
		}
	}
	if err := os.Remove(filepath.Join(repo, ".env")); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, code := runCLIInDir(t, repo, "decrypt", "--identity", identity)
	assertNoSentinels(t, "decrypt without trust state", stdout+stderr)
	if code != exitOutOfSync || !strings.Contains(stderr, "no previously accepted commit is recorded") || !strings.Contains(stderr, "decrypt --accept-changes") {
		t.Fatalf("decrypt without trust state exit = %d, want %d\n%s%s", code, exitOutOfSync, stdout, stderr)
	}
	if _, err := os.Stat(filepath.Join(repo, ".env")); !os.IsNotExist(err) {
		t.Fatalf("refused decrypt wrote plaintext: %v", err)
	}
	for _, args := range [][]string{
		{"decrypt", "--accept-changes", "--identity", identity},
		{"decrypt", "--identity", identity},
	} {
		stdout, stderr, code = runCLIInDir(t, repo, args...)
		assertNoSentinels(t, strings.Join(args, " "), stdout+stderr)
		if code != exitOK {
			t.Fatalf("%v exit = %d\n%s%s", args, code, stdout, stderr)
		}
	}
}

// Decision (b): a developer's own uncommitted encrypt leaves decrypt a no-op,
// but decrypt never installs uncommitted ciphertext.
func TestPlainDecryptAfterOwnUncommittedEncrypt(t *testing.T) {
	fixture := setupTrustedRepo(t, "A=old\n")
	envPath := filepath.Join(fixture.repo, ".env")
	if err := os.WriteFile(envPath, []byte("A="+aliceSecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, code := runCLICombinedInDir(t, fixture.repo, "encrypt", "--identity", fixture.identity); code != exitOK {
		t.Fatalf("encrypt: %d\n%s", code, out)
	}

	stdout, stderr, code := runCLIInDir(t, fixture.repo, "decrypt", "--identity", fixture.identity)
	assertNoSentinels(t, "decrypt after own encrypt", stdout+stderr)
	if code != exitOK || !strings.Contains(stdout, ".env unchanged: it already matches the uncommitted .env.age") {
		t.Fatalf("decrypt after own uncommitted encrypt exit = %d\n%s%s", code, stdout, stderr)
	}
	if got, _ := os.ReadFile(envPath); string(got) != "A="+aliceSecret+"\n" {
		t.Fatal("decrypt replaced newer local plaintext with the committed snapshot")
	}

	// With the plaintext gone there is nothing to keep, and the committed
	// snapshot is older than the uncommitted ciphertext: refuse.
	if err := os.Remove(envPath); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code = runCLIInDir(t, fixture.repo, "decrypt", "--identity", fixture.identity)
	assertNoSentinels(t, "decrypt with missing plaintext", stdout+stderr)
	if code != exitOutOfSync || !strings.Contains(stderr, "uncommitted ciphertext .env.age changed keys: ~ A; local .env is missing") {
		t.Fatalf("decrypt over uncommitted ciphertext exit = %d, want %d\n%s%s", code, exitOutOfSync, stdout, stderr)
	}
	if _, err := os.Stat(envPath); !os.IsNotExist(err) {
		t.Fatalf("refused decrypt wrote plaintext: %v", err)
	}

	// Committing and accepting is the documented way forward.
	for _, args := range [][]string{{"add", "-A", ".env.age", ".env.age.sig", ".envguardian"}, {"commit", "-q", "-m", "rotate A"}} {
		if out, code := run(t, fixture.repo, "git", args...); code != 0 {
			t.Fatalf("git %v: %d\n%s", args, code, out)
		}
	}
	if out, code := runCLICombinedInDir(t, fixture.repo, "decrypt", "--accept-changes", "--identity", fixture.identity); code != exitOK {
		assertNoSentinels(t, "accept own change", out)
		t.Fatalf("accept own change: %d\n%s", code, out)
	}
	if got, _ := os.ReadFile(envPath); string(got) != "A="+aliceSecret+"\n" {
		t.Fatal("accepted decrypt did not restore the committed plaintext")
	}
}

// Decision (c): outside a Git repository there is no branch to receive, so
// decrypt keeps reading the files on disk.
func TestPlainDecryptOutsideGitRepository(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if _, inRepo, err := gitWorkTree(dir); inRepo || err != nil {
		t.Fatalf("precondition: %s must be outside any Git repository (inRepo=%v, err=%v)", dir, inRepo, err)
	}
	idPath := setupRepo(t, dir, "A="+aliceSecret+"\n")
	if err := os.Remove(filepath.Join(dir, ".env")); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code := runCLI(t, "decrypt", "--identity", idPath)
	assertNoSentinels(t, "decrypt outside Git", stdout+stderr)
	if code != exitOK {
		t.Fatalf("decrypt outside Git exit = %d\n%s%s", code, stdout, stderr)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, ".env")); string(got) != "A="+aliceSecret+"\n" {
		t.Fatal("decrypt outside Git did not restore plaintext")
	}
}

// A .git entry that Git cannot open must not be mistaken for "not a
// repository": the trust check could not run, so decrypt fails closed.
func TestPlainDecryptFailsClosedWhenGitCannotOpenRepository(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	idPath := setupRepo(t, dir, "A="+aliceSecret+"\n")
	if err := os.Remove(filepath.Join(dir, ".env")); err != nil {
		t.Fatal(err)
	}
	broken := "gitdir: " + filepath.ToSlash(filepath.Join(dir, "missing-git-dir")) + "\n"
	if err := os.WriteFile(filepath.Join(dir, ".git"), []byte(broken), 0o644); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code := runCLI(t, "decrypt", "--identity", idPath)
	assertNoSentinels(t, "decrypt with unreadable repository", stdout+stderr)
	if code != exitOutOfSync || !strings.Contains(stderr, "Git could not open it") {
		t.Fatalf("decrypt with unreadable repository exit = %d, want %d\n%s%s", code, exitOutOfSync, stdout, stderr)
	}
	if _, err := os.Stat(filepath.Join(dir, ".env")); !os.IsNotExist(err) {
		t.Fatalf("fail-closed decrypt wrote plaintext: %v", err)
	}
}
