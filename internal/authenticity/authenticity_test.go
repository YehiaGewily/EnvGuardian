package authenticity

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/YehiaGewily/envguardian/internal/keys"
)

type signingFixture struct {
	identity  *keys.Identity
	recipient keys.Recipient
}

func newSigningFixture(t *testing.T, name string) signingFixture {
	t.Helper()
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen is required")
	}
	privatePath := filepath.Join(t.TempDir(), "id_ed25519")
	cmd := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", privatePath) // #nosec G204 -- test-owned path
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generate SSH identity: %v\n%s", err, output)
	}
	publicKey, err := os.ReadFile(privatePath + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := keys.ResolveIdentity(privatePath, nil)
	if err != nil {
		t.Fatal(err)
	}
	return signingFixture{
		identity: identity,
		recipient: keys.Recipient{
			Name: name, Keys: []string{strings.TrimSpace(string(publicKey))}, Source: "test",
			AddedAt: "2026-07-29", AddedBy: "test",
		},
	}
}

func testBinding(rf *keys.RecipientsFile) Binding {
	return Binding{
		RecipientsFingerprint: rf.Fingerprint(), ConfigPath: ".envguardian/config.toml",
		PlaintextPath: ".env", CiphertextPath: ".env.age",
	}
}

func TestSignAndVerifyCurrentRecipient(t *testing.T) {
	alice := newSigningFixture(t, "alice")
	rf := &keys.RecipientsFile{Recipients: []keys.Recipient{alice.recipient}}
	ciphertext := []byte("public ciphertext bytes")
	signature, signer, err := Sign(SignerFromIdentity(alice.identity), rf, testBinding(rf), ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if signer != "alice" {
		t.Fatalf("signer=%q, want alice", signer)
	}
	verified, err := Verify(signature, rf, testBinding(rf), ciphertext)
	if err != nil || verified != "alice" {
		t.Fatalf("Verify signer=%q error=%v", verified, err)
	}
}

func TestSignatureBindingRejectsDifferentCiphertextAndMapping(t *testing.T) {
	alice := newSigningFixture(t, "alice")
	rf := &keys.RecipientsFile{Recipients: []keys.Recipient{alice.recipient}}
	binding := testBinding(rf)
	signature, _, err := Sign(SignerFromIdentity(alice.identity), rf, binding, []byte("ciphertext one"))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		binding    Binding
		ciphertext []byte
	}{
		{name: "different ciphertext", binding: binding, ciphertext: []byte("ciphertext two")},
		{name: "different config", binding: func() Binding { changed := binding; changed.ConfigPath = ".envguardian/other.toml"; return changed }(), ciphertext: []byte("ciphertext one")},
		{name: "different plaintext mapping", binding: func() Binding { changed := binding; changed.PlaintextPath = "config/dev/.env"; return changed }(), ciphertext: []byte("ciphertext one")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Verify(signature, rf, tt.binding, tt.ciphertext); err == nil {
				t.Fatal("re-pointed signature verified")
			}
		})
	}
}

func TestNonRecipientAndRevokedSignerRejected(t *testing.T) {
	alice := newSigningFixture(t, "alice")
	bob := newSigningFixture(t, "bob")
	withAlice := &keys.RecipientsFile{Recipients: []keys.Recipient{alice.recipient, bob.recipient}}
	binding := testBinding(withAlice)
	signature, _, err := Sign(SignerFromIdentity(alice.identity), withAlice, binding, []byte("ciphertext"))
	if err != nil {
		t.Fatal(err)
	}
	bobOnly := &keys.RecipientsFile{Recipients: []keys.Recipient{bob.recipient}}
	revokedBinding := testBinding(bobOnly)
	if _, err := Verify(signature, bobOnly, revokedBinding, []byte("ciphertext")); err == nil {
		t.Fatal("revoked recipient's signature verified")
	}

	attacker := newSigningFixture(t, "attacker")
	attackerFile := &keys.RecipientsFile{Recipients: []keys.Recipient{attacker.recipient}}
	attackerSignature, _, err := Sign(SignerFromIdentity(attacker.identity), attackerFile, testBinding(attackerFile), []byte("ciphertext"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(attackerSignature, bobOnly, testBinding(bobOnly), []byte("ciphertext")); err == nil {
		t.Fatal("non-recipient signature verified")
	}
}

func TestPayloadContainsNoPlaintextSentinel(t *testing.T) {
	rf := &keys.RecipientsFile{Recipients: []keys.Recipient{{Name: "n", Key: "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"}}}
	payload := Payload(testBinding(rf), []byte("ciphertext-does-not-contain-plaintext"))
	if strings.Contains(string(payload), "SENTINEL-PLAINTEXT-SECRET") {
		t.Fatal("signature payload contains plaintext sentinel")
	}
}

func TestSignatureNameCanonicalizesSeparators(t *testing.T) {
	tests := map[string]string{
		".env.age":            ".env.age.sig",
		`config\dev\.env.age`: "config/dev/.env.age.sig",
		"./config//.env.age":  "config/.env.age.sig",
	}
	for input, want := range tests {
		if got := SignatureName(input); got != want {
			t.Errorf("SignatureName(%q)=%q, want %q", input, got, want)
		}
	}
}

func TestSignRejectsUnusableIdentities(t *testing.T) {
	alice := newSigningFixture(t, "alice")
	outsider := newSigningFixture(t, "outsider")
	rf := &keys.RecipientsFile{Recipients: []keys.Recipient{alice.recipient}}
	ageOnly := &keys.Identity{Recipient: "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"}
	tests := []struct {
		name     string
		identity *keys.Identity
		reason   string
	}{
		{name: "nil identity", identity: nil, reason: "sealing requires an SSH key"},
		{name: "age identity", identity: ageOnly, reason: "sealing requires an SSH key"},
		{name: "non-recipient", identity: outsider.identity, reason: "not a current recipient"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := Sign(SignerFromIdentity(tt.identity), rf, testBinding(rf), []byte("ciphertext"))
			var sigErr *SignatureError
			if !errors.As(err, &sigErr) {
				t.Fatalf("Sign error=%v, want *SignatureError", err)
			}
			if !strings.Contains(err.Error(), tt.reason) || !strings.Contains(err.Error(), ".env.age") {
				t.Fatalf("error %q does not name path and reason %q", err, tt.reason)
			}
		})
	}
}

func TestSignReportsSSHKeygenFailureWithoutKeyMaterial(t *testing.T) {
	alice := newSigningFixture(t, "alice")
	rf := &keys.RecipientsFile{Recipients: []keys.Recipient{alice.recipient}}
	keyBytes, err := os.ReadFile(alice.identity.SSHKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(alice.identity.SSHKeyPath); err != nil {
		t.Fatal(err)
	}
	_, _, err = Sign(SignerFromIdentity(alice.identity), rf, testBinding(rf), []byte("ciphertext"))
	var sigErr *SignatureError
	if !errors.As(err, &sigErr) || sigErr.Unwrap() == nil {
		t.Fatalf("Sign error=%v, want wrapped *SignatureError", err)
	}
	if strings.Contains(err.Error(), strings.TrimSpace(string(keyBytes))) {
		t.Fatal("signing error disclosed private key material")
	}
}

func TestVerifyRejectsUnverifiableInputs(t *testing.T) {
	alice := newSigningFixture(t, "alice")
	rf := &keys.RecipientsFile{Recipients: []keys.Recipient{alice.recipient}}
	ageOnly := &keys.RecipientsFile{Recipients: []keys.Recipient{{Name: "n", Key: "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"}}}
	signature, _, err := Sign(SignerFromIdentity(alice.identity), rf, testBinding(rf), []byte("ciphertext"))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		signature  []byte
		recipients *keys.RecipientsFile
		reason     string
	}{
		{name: "empty signature", signature: []byte(" \n"), recipients: rf, reason: "empty"},
		{name: "no SSH recipients", signature: signature, recipients: ageOnly, reason: "no current recipient has an SSH key"},
		{name: "garbage signature", signature: []byte("not an ssh signature"), recipients: rf, reason: "invalid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Verify(tt.signature, tt.recipients, testBinding(tt.recipients), []byte("ciphertext"))
			var sigErr *SignatureError
			if !errors.As(err, &sigErr) || !strings.Contains(err.Error(), tt.reason) {
				t.Fatalf("Verify error=%v, want *SignatureError mentioning %q", err, tt.reason)
			}
		})
	}
}

func TestMissingSSHKeygenFailsClosed(t *testing.T) {
	alice := newSigningFixture(t, "alice")
	rf := &keys.RecipientsFile{Recipients: []keys.Recipient{alice.recipient}}
	signature, _, err := Sign(SignerFromIdentity(alice.identity), rf, testBinding(rf), []byte("ciphertext"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", t.TempDir())
	if _, _, err := Sign(SignerFromIdentity(alice.identity), rf, testBinding(rf), []byte("ciphertext")); err == nil || !strings.Contains(err.Error(), "ssh-keygen is unavailable") {
		t.Fatalf("Sign without ssh-keygen error=%v", err)
	}
	if _, err := Verify(signature, rf, testBinding(rf), []byte("ciphertext")); err == nil || !strings.Contains(err.Error(), "ssh-keygen is unavailable") {
		t.Fatalf("Verify without ssh-keygen error=%v", err)
	}
}

func TestSignerFromPublicKeyFile(t *testing.T) {
	alice := newSigningFixture(t, "alice")
	pub := alice.identity.SSHKeyPath + ".pub"
	signer, err := SignerFromPublicKeyFile(pub)
	if err != nil {
		t.Fatal(err)
	}
	if signer.KeyPath != pub || !strings.HasPrefix(signer.PublicKey, "ssh-ed25519 ") {
		t.Fatalf("signer = %+v", signer)
	}
	privateBytes, err := os.ReadFile(alice.identity.SSHKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	ageFile := filepath.Join(t.TempDir(), "age.pub")
	if err := os.WriteFile(ageFile, []byte("age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"private key file": alice.identity.SSHKeyPath,
		"age key":          ageFile,
		"missing file":     filepath.Join(t.TempDir(), "absent.pub"),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := SignerFromPublicKeyFile(path)
			if err == nil {
				t.Fatal("unusable signing key accepted")
			}
			if strings.Contains(err.Error(), strings.TrimSpace(string(privateBytes))) {
				t.Fatal("error disclosed private key material")
			}
		})
	}
}

// startAgent runs a private ssh-agent for the test and points SSH_AUTH_SOCK at
// it. It skips where OpenSSH's agent cannot listen on a Unix socket.
func startAgent(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("ssh-agent on Windows is a system service, not a per-test socket")
	}
	agentPath, err := exec.LookPath("ssh-agent")
	if err != nil {
		t.Skip("ssh-agent is required")
	}
	dir, err := os.MkdirTemp("", "eg-agent-") // short path: Unix sockets have a small length limit
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "agent.sock")
	agent := exec.Command(agentPath, "-D", "-a", socket) // #nosec G204 -- test-owned socket path
	if err := agent.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = agent.Process.Kill(); _ = agent.Wait() })
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(socket); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Setenv("SSH_AUTH_SOCK", socket)
}

func TestSignThroughAgentWithPublicKeyOnly(t *testing.T) {
	alice := newSigningFixture(t, "alice")
	startAgent(t)
	rf := &keys.RecipientsFile{Recipients: []keys.Recipient{alice.recipient}}
	signer, err := SignerFromPublicKeyFile(alice.identity.SSHKeyPath + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	// Move the private key away so ssh-keygen cannot fall back to the file
	// next to the public key; only the agent can sign after this.
	moved := filepath.Join(t.TempDir(), "agent-only-key")
	if err := os.Rename(alice.identity.SSHKeyPath, moved); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Sign(signer, rf, testBinding(rf), []byte("ciphertext")); err == nil {
		t.Fatal("signed with a public key the agent does not hold")
	}
	if out, err := exec.Command("ssh-add", moved).CombinedOutput(); err != nil { // #nosec G204 -- test-owned key
		t.Fatalf("ssh-add: %v\n%s", err, out)
	}
	signature, name, err := Sign(signer, rf, testBinding(rf), []byte("ciphertext"))
	if err != nil {
		t.Fatalf("agent signing: %v", err)
	}
	if name != "alice" {
		t.Fatalf("signer name=%q", name)
	}
	if verified, err := Verify(signature, rf, testBinding(rf), []byte("ciphertext")); err != nil || verified != "alice" {
		t.Fatalf("Verify agent signature: %q %v", verified, err)
	}
}
