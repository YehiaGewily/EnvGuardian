package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSigningKeyFlagSelectsRecipientPublicKey(t *testing.T) {
	repo, identity := setupCommittedHookRepo(t)
	if err := os.WriteFile(filepath.Join(repo, ".env"), []byte("A=sentinel-signing-two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	outsider := filepath.Join(t.TempDir(), "outsider")
	writeAgeID(t, outsider)
	ageKey := filepath.Join(t.TempDir(), "age.pub")
	if err := os.WriteFile(ageKey, []byte("age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(repo, ".env.age"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name, key string
		code      int
		want      string
	}{
		{name: "not an SSH public key", key: ageKey, code: exitConfig, want: "SSH public key file"},
		{name: "non-recipient", key: outsider + ".pub", code: exitSignature, want: "not a current recipient"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			out, code := runCLICombinedInDir(t, repo, "encrypt", "--identity", identity, "--signing-key", tt.key)
			if code != tt.code || !strings.Contains(out, tt.want) || strings.Contains(out, "sentinel-signing-two") {
				t.Fatalf("exit=%d, want %d with %q:\n%s", code, tt.code, tt.want, out)
			}
			after, err := os.ReadFile(filepath.Join(repo, ".env.age"))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("ciphertext changed although signing failed")
			}
		})
	}

	t.Setenv("ENVGUARDIAN_SIGNING_KEY", identity+".pub")
	if out, code := runCLICombinedInDir(t, repo, "encrypt", "--identity", identity); code != exitOK {
		t.Fatalf("encrypt with ENVGUARDIAN_SIGNING_KEY: exit=%d\n%s", code, out)
	}
	if out, code := runCLICombinedInDir(t, repo, "check", "--identity", identity); code != exitOK || !strings.Contains(out, `signed by current recipient "alice"`) {
		t.Fatalf("check after signing-key seal: exit=%d\n%s", code, out)
	}
}
