package keys

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/armor"
	gossh "golang.org/x/crypto/ssh"
)

// stubPrompter returns a fixed passphrase and controllable interactivity.
type stubPrompter struct {
	interactive bool
	pass        string
	asked       bool
	err         error
}

func (s *stubPrompter) Interactive() bool { return s.interactive }
func (s *stubPrompter) Passphrase(string) ([]byte, error) {
	s.asked = true
	return []byte(s.pass), s.err
}

func writeAgeIdentity(t *testing.T, dir string) (path, recipient string) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(dir, "identity.txt")
	if err := os.WriteFile(path, []byte(id.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, id.Recipient().String()
}

func writeSSHIdentity(t *testing.T, dir string) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := gossh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestResolveIdentityFlag(t *testing.T) {
	dir := t.TempDir()
	path, _ := writeAgeIdentity(t, dir)

	id, err := ResolveIdentity(path, &stubPrompter{interactive: true})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(id.Identities) != 1 {
		t.Errorf("got %d identities, want 1", len(id.Identities))
	}
	if id.Label != path {
		t.Errorf("label = %q, want %q", id.Label, path)
	}
}

func TestResolveIdentityEnvRawMaterial(t *testing.T) {
	ageID, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("ENVGUARDIAN_IDENTITY", ageID.String())

	id, err := ResolveIdentity("", &stubPrompter{interactive: true})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if id.Label != "$ENVGUARDIAN_IDENTITY" {
		t.Errorf("label = %q, want $ENVGUARDIAN_IDENTITY", id.Label)
	}
}

func TestResolveIdentitySSH(t *testing.T) {
	dir := t.TempDir()
	path := writeSSHIdentity(t, dir)
	id, err := ResolveIdentity(path, &stubPrompter{interactive: true})
	if err != nil {
		t.Fatalf("resolve ssh: %v", err)
	}
	if len(id.Identities) != 1 {
		t.Errorf("got %d identities, want 1", len(id.Identities))
	}
	wantPath, err := filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	if id.SSHKeyPath != wantPath {
		t.Errorf("SSHKeyPath = %q, want %q", id.SSHKeyPath, wantPath)
	}
}

func TestResolveIdentityNoneFound(t *testing.T) {
	// Point HOME at an empty dir and clear the env so nothing resolves.
	t.Setenv("ENVGUARDIAN_IDENTITY", "")
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir()) // Windows

	_, err := ResolveIdentity("", &stubPrompter{interactive: true})
	var nie *NoIdentityError
	if !errors.As(err, &nie) {
		t.Fatalf("error type = %T, want *NoIdentityError", err)
	}
	if len(nie.Attempts) != 5 {
		t.Fatalf("tried %d sources, want 5", len(nie.Attempts))
	}
	msg := err.Error()
	for _, want := range []string{
		"no usable identity found",
		"--identity flag",
		"$ENVGUARDIAN_IDENTITY",
		"id_ed25519",
		"next:",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("message missing %q:\n%s", want, msg)
		}
	}
}

func TestIdentityErrorsDoNotExposeKeyMaterial(t *testing.T) {
	const sentinel = "SENTINEL-PRIVATE-KEY-MATERIAL-DO-NOT-PRINT"
	t.Setenv("ENVGUARDIAN_IDENTITY", sentinel)
	_, err := ResolveIdentity("", &stubPrompter{interactive: false})
	if err == nil {
		t.Fatal("expected malformed identity error")
	}
	if strings.Contains(err.Error(), sentinel) {
		t.Fatal("identity diagnostic exposed private key material")
	}
	if !strings.Contains(err.Error(), string(ReasonMalformed)) {
		t.Fatalf("identity diagnostic omitted its safe error category: %v", err)
	}
}

func TestResolvePassphraseNoTTY(t *testing.T) {
	// Isolate so only the --identity flag source is viable.
	t.Setenv("ENVGUARDIAN_IDENTITY", "")
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir())

	dir := t.TempDir()

	// Write a passphrase-protected age identity: an armored age file (scrypt)
	// whose plaintext is a real age identity.
	realID, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	rcpt, err := age.NewScryptRecipient("hunter2")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	aw := armor.NewWriter(&buf)
	w, err := age.Encrypt(aw, rcpt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(realID.String() + "\n")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := aw.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "identity.txt")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	// Non-interactive: must fail with ErrPassphraseRequired.
	_, err = ResolveIdentity(path, &stubPrompter{interactive: false})
	if !errors.Is(err, ErrPassphraseRequired) {
		t.Fatalf("non-TTY error = %v, want ErrPassphraseRequired", err)
	}
	var nie *NoIdentityError
	if !errors.As(err, &nie) {
		t.Fatalf("want *NoIdentityError, got %T", err)
	}
	if nie.Attempts[0].Reason != ReasonNeedsPassphrase {
		t.Errorf("reason = %q, want %q", nie.Attempts[0].Reason, ReasonNeedsPassphrase)
	}

	// Interactive with the right passphrase: must succeed.
	pr := &stubPrompter{interactive: true, pass: "hunter2"}
	id, err := ResolveIdentity(path, pr)
	if err != nil {
		t.Fatalf("interactive resolve: %v", err)
	}
	if !pr.asked {
		t.Error("passphrase was not requested")
	}
	if len(id.Identities) != 1 {
		t.Errorf("got %d identities, want 1", len(id.Identities))
	}
}

func TestResolveEncryptedSSHIdentity(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := gossh.MarshalPrivateKeyWithPassphrase(privateKey, "", []byte("correct horse"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	id, err := ResolveIdentity(path, &stubPrompter{interactive: true, pass: "correct horse"})
	if err != nil {
		t.Fatalf("resolve encrypted SSH identity: %v", err)
	}
	if len(id.Identities) != 1 || !strings.HasPrefix(id.Recipient, "ssh-ed25519 ") {
		t.Fatal("encrypted SSH identity did not produce a usable SSH recipient")
	}
}

func TestEncryptedAgeIdentityFailuresAreSanitized(t *testing.T) {
	realID, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := age.NewScryptRecipient("correct passphrase")
	if err != nil {
		t.Fatal(err)
	}
	var encrypted bytes.Buffer
	writer, err := age.Encrypt(&encrypted, recipient)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte(realID.String())); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "encrypted-age-key")
	if err := os.WriteFile(path, encrypted.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = ResolveIdentity(path, &stubPrompter{interactive: true, pass: "wrong passphrase"})
	if err == nil {
		t.Fatal("wrong passphrase unexpectedly resolved")
	}
	if strings.Contains(err.Error(), realID.String()) {
		t.Fatal("identity error exposed decrypted key material")
	}
	const promptSentinel = "SENTINEL-PROMPTER-SECRET"
	_, err = ResolveIdentity(path, &stubPrompter{interactive: true, err: errors.New(promptSentinel)})
	if err == nil {
		t.Fatal("prompter failure unexpectedly resolved")
	}
	if strings.Contains(err.Error(), promptSentinel) {
		t.Fatal("identity error exposed upstream prompter text")
	}
}
