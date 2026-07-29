package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/YehiaGewily/envguardian/internal/config"
	"github.com/YehiaGewily/envguardian/internal/crypt"
	"github.com/YehiaGewily/envguardian/internal/keys"
)

func prepareMergeRepo(t *testing.T, base string) (repo, bin, identity, mainBranch string, env []string) {
	t.Helper()
	bin = buildBinary(t)
	repo = gitInitRepo(t)
	identity = filepath.Join(repo, "id")
	writeAgeID(t, identity)
	env = append(os.Environ(), "ENVGUARDIAN_IDENTITY="+identity)
	if out, code := run(t, repo, bin, "init", "--identity", identity, "--name", "alice"); code != exitOK {
		t.Fatalf("init: %d\n%s", code, out)
	}
	if err := os.WriteFile(filepath.Join(repo, ".env"), []byte(base), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, code := run(t, repo, bin, "encrypt", "--identity", identity); code != exitOK {
		t.Fatalf("encrypt base: %d\n%s", code, out)
	}
	if out, code := run(t, repo, bin, "merge", "--install"); code != exitOK {
		t.Fatalf("merge --install: %d\n%s", code, out)
	}
	run(t, repo, "git", "add", ".gitattributes", ".envguardian", ".env.age", ".env.age.sig")
	if out, code := runEnv(t, repo, env, "git", "commit", "-m", "base"); code != exitOK {
		t.Fatalf("commit base: %d\n%s", code, out)
	}
	if out, code := run(t, repo, bin, "check", "--identity", identity); code != exitOK {
		t.Fatalf("base check: %d\n%s", code, out)
	}
	mainBranch, _ = run(t, repo, "git", "branch", "--show-current")
	mainBranch = strings.TrimSpace(mainBranch)
	return repo, bin, identity, mainBranch, env
}

func commitEncryptedBranch(t *testing.T, repo, bin, identity string, env []string, content, message string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(repo, ".env"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, code := run(t, repo, bin, "encrypt", "--identity", identity); code != exitOK {
		t.Fatalf("encrypt %s: %d\n%s", message, code, out)
	}
	run(t, repo, "git", "add", ".env.age", ".env.age.sig", ".envguardian/lock.toml")
	if out, code := runEnv(t, repo, env, "git", "commit", "-m", message); code != exitOK {
		t.Fatalf("commit %s: %d\n%s", message, code, out)
	}
}

func TestMergeDriverRealDivergingBranches(t *testing.T) {
	repo, bin, identity, mainBranch, env := prepareMergeRepo(t, "A=base\nB=base\n")
	run(t, repo, "git", "checkout", "-b", "theirs")
	commitEncryptedBranch(t, repo, bin, identity, env, "A=base\nB=theirs\n", "theirs changes B")
	if out, code := run(t, repo, "git", "checkout", mainBranch); code != exitOK {
		t.Fatalf("checkout %s: %d\n%s", mainBranch, code, out)
	}
	if out, code := run(t, repo, bin, "decrypt", "--identity", identity); code != exitOK {
		t.Fatalf("restore main plaintext: %d\n%s", code, out)
	}
	commitEncryptedBranch(t, repo, bin, identity, env, "A=ours\nB=base\n", "ours changes A")

	mergeOut, mergeCode := runEnv(t, repo, env, "git", "merge", "theirs")
	if mergeCode == exitOK || !strings.Contains(mergeOut, "merge --continue") {
		t.Fatalf("Git merge did not pause for finalization: code=%d\n%s", mergeCode, mergeOut)
	}
	if out, errOut, code := runCLIInDir(t, repo, "merge", "--continue", "--identity", identity); code != exitOK {
		t.Fatalf("merge --continue: %d\n%s%s", code, out, errOut)
	}
	if unmerged, _ := run(t, repo, "git", "diff", "--name-only", "--diff-filter=U"); strings.TrimSpace(unmerged) != "" {
		t.Fatalf("unmerged paths remain: %s", unmerged)
	}
	if out, code := run(t, repo, bin, "decrypt", "--identity", identity); code != exitOK {
		t.Fatalf("decrypt merged result: %d\n%s", code, out)
	}
	plaintext, err := os.ReadFile(filepath.Join(repo, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(plaintext)
	if !strings.Contains(text, "A=ours") || !strings.Contains(text, "B=theirs") {
		t.Fatalf("merged plaintext lacks one-sided changes")
	}
	if out, code := run(t, repo, bin, "check", "--identity", identity); code != exitOK {
		t.Fatalf("check after merge: %d\n%s", code, out)
	}
}

func TestMergeDriverRealConflictPrintsKeyNamesOnly(t *testing.T) {
	repo, bin, identity, mainBranch, env := prepareMergeRepo(t, "TOKEN=base-secret\n")
	run(t, repo, "git", "checkout", "-b", "theirs")
	commitEncryptedBranch(t, repo, bin, identity, env, "TOKEN=theirs-secret\n", "theirs changes token")
	if out, code := run(t, repo, "git", "checkout", mainBranch); code != exitOK {
		t.Fatalf("checkout %s: %d\n%s", mainBranch, code, out)
	}
	if out, code := run(t, repo, bin, "decrypt", "--identity", identity); code != exitOK {
		t.Fatalf("restore main plaintext: %d\n%s", code, out)
	}
	commitEncryptedBranch(t, repo, bin, identity, env, "TOKEN=ours-secret\n", "ours changes token")

	mergeOut, mergeCode := runEnv(t, repo, env, "git", "merge", "theirs")
	if mergeCode == exitOK || !strings.Contains(mergeOut, "TOKEN") {
		t.Fatalf("expected key-name conflict: code=%d\n%s", mergeCode, mergeOut)
	}
	continueStdout, continueStderr, continueCode := runCLIInDir(t, repo, "merge", "--continue", "--identity", identity)
	continueOut := continueStdout + continueStderr
	if continueCode == exitOK || !strings.Contains(continueOut, "TOKEN") {
		t.Fatalf("continue did not preserve key-name conflict: code=%d\n%s", continueCode, continueOut)
	}
	for _, secret := range []string{"base-secret", "ours-secret", "theirs-secret"} {
		if strings.Contains(mergeOut+continueOut, secret) {
			t.Fatalf("merge diagnostics exposed a secret value")
		}
	}
}

func TestInstallMergeDriverInProcess(t *testing.T) {
	repo := gitInitRepo(t)
	stdout, stderr, code := runCLIInDir(t, repo, "merge", "--install")
	if code != exitOK {
		t.Fatalf("merge --install: %d\n%s%s", code, stdout, stderr)
	}
	attributes, err := os.ReadFile(filepath.Join(repo, ".gitattributes"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"*.age -text merge=envguardian", "*.age.sig -text merge=envguardian-generated", ".envguardian/lock.toml text eol=lf merge=envguardian-generated"} {
		if !strings.Contains(string(attributes), want) {
			t.Fatalf("attributes missing %q:\n%s", want, attributes)
		}
	}
	configured, code := run(t, repo, "git", "config", "--local", "--get", "merge.envguardian.driver")
	if code != exitOK || !strings.Contains(configured, "merge-driver") {
		t.Fatalf("local merge driver was not configured: %d %s", code, configured)
	}
	if _, _, code := runCLIInDir(t, repo, "merge"); code != exitConfig {
		t.Fatalf("merge without mode exit = %d", code)
	}
	if _, _, code := runCLIInDir(t, repo, "merge", "--install", "--continue"); code != exitConfig {
		t.Fatalf("merge with conflicting modes exit = %d", code)
	}
}

func TestHiddenMergeDriverInProcess(t *testing.T) {
	repo, _, identityPath, _, _ := prepareMergeRepo(t, "A=base\nB=base\n")
	paths := config.PathsFor(repo)
	rf, err := keys.LoadRecipients(paths.Recipients)
	if err != nil {
		t.Fatal(err)
	}
	recipients, err := rf.AgeRecipients()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := keys.ResolveIdentity(identityPath, keys.DefaultPrompter())
	if err != nil {
		t.Fatal(err)
	}
	makeCiphertext := func(name, content string) string {
		t.Helper()
		plain := filepath.Join(repo, name+".env")
		cipher := filepath.Join(repo, name+".age")
		if err := os.WriteFile(plain, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := crypt.Seal(crypt.Config{
			LockPath: filepath.Join(repo, name+".lock"), Fingerprint: rf.Fingerprint(),
		}, recipients, plain, cipher); err != nil {
			t.Fatal(err)
		}
		return cipher
	}
	base := makeCiphertext("base-side", "A=base\nB=base\n")
	ours := makeCiphertext("ours-side", "A=ours\nB=base\n")
	theirs := makeCiphertext("theirs-side", "A=base\nB=theirs\n")
	oursBytes, err := os.ReadFile(ours)
	if err != nil {
		t.Fatal(err)
	}
	managed := filepath.Join(repo, ".env.age")
	if err := os.WriteFile(managed, oursBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code := runCLIInDir(t, repo, "merge-driver", base, managed, theirs, ".env.age", "--identity", identityPath)
	if code != exitOutOfSync || !strings.Contains(stdout+stderr, "intentionally paused") {
		t.Fatalf("hidden merge driver: %d\n%s%s", code, stdout, stderr)
	}
	mergedCiphertext, err := os.ReadFile(managed)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, _, err := crypt.DecryptBytesToDotenv(identity.Identities, mergedCiphertext)
	if err != nil {
		t.Fatal(err)
	}
	if text := string(plaintext); !strings.Contains(text, "A=ours") || !strings.Contains(text, "B=theirs") {
		t.Fatal("hidden driver did not retain both independent changes")
	}

	conflicting := makeCiphertext("conflicting-side", "A=theirs-conflict\nB=base\n")
	if err := os.WriteFile(managed, oursBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code = runCLIInDir(t, repo, "merge-driver", base, managed, conflicting, ".env.age", "--identity", identityPath)
	if code != exitOutOfSync || !strings.Contains(stdout+stderr, "A") || strings.Contains(stdout+stderr, "theirs-conflict") {
		t.Fatalf("hidden conflict driver: %d\n%s%s", code, stdout, stderr)
	}
}

func TestMergeHelperFailureAndGeneratedPaths(t *testing.T) {
	repo := gitInitRepo(t)
	if _, _, code := runCLIInDir(t, repo, "merge-generated-driver", "base", "ours", "theirs", ".env.age"); code != exitOK {
		t.Fatalf("generated metadata driver exit = %d", code)
	}
	if _, err := resolveMergePath(repo, filepath.Join(filepath.Dir(repo), "outside.age")); err == nil {
		t.Fatal("merge output outside the repository was accepted")
	}
	empty := filepath.Join(repo, "empty.age")
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if file, err := decryptMergeSide(&keys.Identity{}, empty, ".env.age", "base"); err != nil || file != nil {
		t.Fatalf("empty deletion side = %+v, %v", file, err)
	}
	cfg := &config.Config{Files: []config.FilePair{{Ciphertext: "config/app.age"}}}
	if _, ok := configuredCiphertext(cfg, "config/app.age"); !ok {
		t.Fatal("configured ciphertext was not found")
	}
	if _, ok := configuredCiphertext(cfg, "other.age"); ok {
		t.Fatal("unconfigured ciphertext was accepted")
	}
	if _, exists, err := gitStageBlob(repo, 2, "missing.age"); err != nil || exists {
		t.Fatalf("missing Git stage = exists %v, err %v", exists, err)
	}
	if conflict, err := hasUnmergedPath(repo, "missing.age"); err != nil || conflict {
		t.Fatalf("missing unmerged path = %v, %v", conflict, err)
	}
	err := mergeConflictError("app.age", []string{"Z_KEY", "A_KEY"})
	if !strings.Contains(err.Error(), "A_KEY, Z_KEY") {
		t.Fatalf("conflict keys were not sorted: %v", err)
	}
}

func TestResolveMergePathCanonicalizesFilesystemAliases(t *testing.T) {
	realRoot := t.TempDir()
	managed := filepath.Join(realRoot, ".env.age")
	if err := os.WriteFile(managed, []byte("ciphertext"), 0o600); err != nil {
		t.Fatal(err)
	}

	aliasParent := t.TempDir()
	aliasRoot := filepath.Join(aliasParent, "repo-alias")
	if err := os.Symlink(realRoot, aliasRoot); err != nil {
		t.Skipf("filesystem aliases are unavailable: %v", err)
	}
	canonicalRoot, err := filepath.EvalSymlinks(realRoot)
	if err != nil {
		t.Fatal(err)
	}
	got, err := resolveMergePath(canonicalRoot, filepath.Join(aliasRoot, ".env.age"))
	if err != nil {
		t.Fatalf("resolve aliased merge path: %v", err)
	}
	want, err := filepath.EvalSymlinks(managed)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("resolved path = %q, want %q", got, want)
	}
}

func TestMergeContinueRejectsUnsignedBranchSide(t *testing.T) {
	repo, bin, identity, mainBranch, env := prepareMergeRepo(t, "A=base\nB=base\n")
	run(t, repo, "git", "checkout", "-b", "unsigned-side")
	commitEncryptedBranch(t, repo, bin, identity, env, "A=base\nB=theirs\n", "theirs changes B")
	if out, code := run(t, repo, "git", "rm", ".env.age.sig"); code != exitOK {
		t.Fatalf("remove branch signature: %d\n%s", code, out)
	}
	if out, code := runEnv(t, repo, env, "git", "commit", "-m", "remove signature"); code != exitOK {
		t.Fatalf("commit unsigned side: %d\n%s", code, out)
	}
	if out, code := run(t, repo, "git", "checkout", mainBranch); code != exitOK {
		t.Fatalf("checkout main: %d\n%s", code, out)
	}
	if out, code := run(t, repo, bin, "decrypt", "--identity", identity); code != exitOK {
		t.Fatalf("restore main plaintext: %d\n%s", code, out)
	}
	commitEncryptedBranch(t, repo, bin, identity, env, "A=ours\nB=base\n", "ours changes A")
	if _, code := runEnv(t, repo, env, "git", "merge", "unsigned-side"); code == exitOK {
		t.Fatal("Git merge did not pause")
	}
	stdout, stderr, code := runCLIInDir(t, repo, "merge", "--continue", "--identity", identity)
	if code != exitSignature || !strings.Contains(stdout+stderr, missingSignatureFailure) {
		t.Fatalf("unsigned merge side exit=%d\n%s%s", code, stdout, stderr)
	}
}
