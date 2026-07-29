package authenticity

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

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
	signature, signer, err := Sign(alice.identity, rf, testBinding(rf), ciphertext)
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
	signature, _, err := Sign(alice.identity, rf, binding, []byte("ciphertext one"))
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
	signature, _, err := Sign(alice.identity, withAlice, binding, []byte("ciphertext"))
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
	attackerSignature, _, err := Sign(attacker.identity, attackerFile, testBinding(attackerFile), []byte("ciphertext"))
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
