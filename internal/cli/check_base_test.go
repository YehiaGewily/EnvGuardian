package cli

import (
	"strings"
	"testing"
)

func TestCheckBaseRejectsSelfAddedRecipientBranch(t *testing.T) {
	fx := setupHostileBranch(t)
	if out, code := runEnv(t, fx.repo, fx.malloryEnv, "git", "checkout", "-q", fx.branch); code != 0 {
		t.Fatalf("checkout mallory branch: %d\n%s", code, out)
	}
	if out, code := runCLICombinedInDir(t, fx.repo, "check", "--structural-only"); code != exitOK {
		t.Fatalf("plain structural check should pass against the branch's own recipients: %d\n%s", code, out)
	}
	out, code := runCLICombinedInDir(t, fx.repo, "check", "--structural-only", "--base", fx.mainBranch)
	assertNoSentinels(t, "check --base", out)
	if code != exitSignature {
		t.Fatalf("check --base exit=%d, want %d\n%s", code, exitSignature, out)
	}
	for _, want := range []string{"recipient added: mallory", "not signed by a recipient trusted at base"} {
		if !strings.Contains(out, want) {
			t.Fatalf("check --base output missing %q:\n%s", want, out)
		}
	}
}

func TestCheckBaseAcceptsChangeSignedByBaseRecipient(t *testing.T) {
	fx := setupHostileBranch(t)
	if out, code := runEnv(t, fx.repo, fx.aliceEnv, "git", "checkout", "-q", "-b", "alice-change", fx.mainBranch); code != 0 {
		t.Fatalf("create alice branch: %d\n%s", code, out)
	}
	if out, code := runCLICombinedInDir(t, fx.repo, "check", "--structural-only", "--base", "HEAD"); code != exitOK || !strings.Contains(out, "unchanged since base") {
		t.Fatalf("unchanged snapshot against itself: %d\n%s", code, out)
	}
	fx.writePlaintext(t, []byte("API_TOKEN="+aliceSecret+"-rotated\nDB_HOST=localhost\n"))
	if out, code := runCLICombinedInDir(t, fx.repo, "encrypt", "--identity", fx.aliceID); code != exitOK {
		t.Fatalf("alice encrypt: %d\n%s", code, out)
	}
	if out, code := runEnv(t, fx.repo, fx.aliceEnv, "git", "commit", "-q", "-am", "rotate token"); code != 0 {
		t.Fatalf("commit: %d\n%s", code, out)
	}
	out, code := runCLICombinedInDir(t, fx.repo, "check", "--structural-only", "--base", fx.mainBranch)
	assertNoSentinels(t, "check --base", out)
	if code != exitOK || !strings.Contains(out, `signed by base recipient "alice"`) {
		t.Fatalf("legitimate change rejected: %d\n%s", code, out)
	}
}

func TestCheckBaseFailsClosedOnUnusableBase(t *testing.T) {
	repo, _ := setupCommittedHookRepo(t)
	for _, base := range []string{"does-not-exist", "--output=/tmp/x"} {
		out, code := runCLICombinedInDir(t, repo, "check", "--structural-only", "--base", base)
		if code != exitConfig || !strings.Contains(out, "[FAIL] base") {
			t.Fatalf("check --base %q exit=%d\n%s", base, code, out)
		}
	}
}
