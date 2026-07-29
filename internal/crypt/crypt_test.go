package crypt

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/YehiaGewily/envguardian/internal/keys"
)

// party bundles an age identity with its recipient and key string.
type party struct {
	id  age.Identity
	rec age.Recipient
	key string
}

func newParty(t *testing.T) party {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return party{id: id, rec: id.Recipient(), key: id.Recipient().String()}
}

func recipientsOf(ps ...party) []age.Recipient {
	out := make([]age.Recipient, len(ps))
	for i, p := range ps {
		out[i] = p.rec
	}
	return out
}

func fingerprintOf(ps ...party) string {
	rf := &keys.RecipientsFile{}
	for i, p := range ps {
		rf.Recipients = append(rf.Recipients, keys.Recipient{Name: fmt.Sprintf("r%d", i), Key: p.key})
	}
	return rf.Fingerprint()
}

type sealFixture struct {
	dir, plain, cipher, lock string
}

func newFixture(t *testing.T, content string) sealFixture {
	t.Helper()
	dir := t.TempDir()
	f := sealFixture{
		dir:    dir,
		plain:  filepath.Join(dir, ".env"),
		cipher: filepath.Join(dir, ".env.age"),
		lock:   filepath.Join(dir, "lock.toml"),
	}
	if err := os.WriteFile(f.plain, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f sealFixture) config(identities []age.Identity, fingerprint string) Config {
	return Config{Identities: identities, LockPath: f.lock, Fingerprint: fingerprint, Label: "test"}
}

func TestSealIdempotent(t *testing.T) {
	f := newFixture(t, "A=1\nB=two\n")
	a, b := newParty(t), newParty(t)
	cfg := f.config([]age.Identity{a.id, b.id}, fingerprintOf(a, b))
	recs := recipientsOf(a, b)

	changed, err := Seal(cfg, recs, f.plain, f.cipher)
	if err != nil || !changed {
		t.Fatalf("first seal: changed=%v err=%v, want true/nil", changed, err)
	}
	first, err := os.ReadFile(f.cipher)
	if err != nil {
		t.Fatal(err)
	}
	firstInfo, _ := os.Stat(f.cipher)

	changed, err = Seal(cfg, recs, f.plain, f.cipher)
	if err != nil {
		t.Fatalf("second seal: %v", err)
	}
	if changed {
		t.Error("second seal reported changed=true; must be a no-op")
	}
	second, _ := os.ReadFile(f.cipher)
	secondInfo, _ := os.Stat(f.cipher)

	if string(first) != string(second) {
		t.Error("ciphertext bytes changed on an idempotent re-seal")
	}
	if !firstInfo.ModTime().Equal(secondInfo.ModTime()) {
		t.Error("ciphertext mtime changed on an idempotent re-seal")
	}
}

func TestSealRewritesOnContentChange(t *testing.T) {
	f := newFixture(t, "A=1\n")
	a := newParty(t)
	cfg := f.config([]age.Identity{a.id}, fingerprintOf(a))

	if _, err := Seal(cfg, recipientsOf(a), f.plain, f.cipher); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.plain, []byte("A=2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	changed, err := Seal(cfg, recipientsOf(a), f.plain, f.cipher)
	if err != nil || !changed {
		t.Fatalf("content change: changed=%v err=%v, want true", changed, err)
	}
}

func TestSealRewritesOnRecipientChange(t *testing.T) {
	f := newFixture(t, "A=1\n")
	a, b, c := newParty(t), newParty(t), newParty(t)

	cfg := f.config([]age.Identity{a.id, b.id}, fingerprintOf(a, b))
	if _, err := Seal(cfg, recipientsOf(a, b), f.plain, f.cipher); err != nil {
		t.Fatal(err)
	}

	// Add c: fingerprint changes → must rewrite even though content is identical.
	cfg2 := f.config([]age.Identity{a.id, b.id, c.id}, fingerprintOf(a, b, c))
	changed, err := Seal(cfg2, recipientsOf(a, b, c), f.plain, f.cipher)
	if err != nil || !changed {
		t.Fatalf("recipient change: changed=%v err=%v, want true", changed, err)
	}
}

func TestEveryRecipientCanDecryptRemovedCannot(t *testing.T) {
	f := newFixture(t, "SECRET=value\n")
	a, b, c := newParty(t), newParty(t), newParty(t)

	cfg := f.config([]age.Identity{a.id}, fingerprintOf(a, b, c))
	if _, err := Seal(cfg, recipientsOf(a, b, c), f.plain, f.cipher); err != nil {
		t.Fatal(err)
	}

	// Every recipient can decrypt.
	for i, p := range []party{a, b, c} {
		out := filepath.Join(f.dir, fmt.Sprintf("out%d.env", i))
		oc := Config{Identities: []age.Identity{p.id}, Label: fmt.Sprintf("party%d", i)}
		if err := Open(oc, f.cipher, out); err != nil {
			t.Errorf("party %d could not decrypt: %v", i, err)
			continue
		}
		got, _ := os.ReadFile(out)
		if string(got) != "SECRET=value\n" {
			t.Errorf("party %d decrypted %q", i, got)
		}
	}

	// Re-seal to {a, b} only — c is removed.
	cfg2 := f.config([]age.Identity{a.id}, fingerprintOf(a, b))
	if _, err := Seal(cfg2, recipientsOf(a, b), f.plain, f.cipher); err != nil {
		t.Fatal(err)
	}
	oc := Config{Identities: []age.Identity{c.id}, Label: "removed-c"}
	err := Open(oc, f.cipher, filepath.Join(f.dir, "denied.env"))
	if !errors.Is(err, ErrNotARecipient) {
		t.Fatalf("removed recipient error = %v, want ErrNotARecipient", err)
	}
}

func TestSealCannotDecryptPolicy(t *testing.T) {
	f := newFixture(t, "A=1\n")
	a := newParty(t)
	cfg := f.config([]age.Identity{a.id}, fingerprintOf(a))
	if _, err := Seal(cfg, recipientsOf(a), f.plain, f.cipher); err != nil {
		t.Fatal(err)
	}

	// No identity, same recipients+content → cannot verify → error by default.
	noID := f.config(nil, fingerprintOf(a))
	if _, err := Seal(noID, recipientsOf(a), f.plain, f.cipher); err == nil {
		t.Fatal("expected an error when the ciphertext can't be verified")
	}

	// --force writes blind and logs loudly.
	var logged []string
	forced := noID
	forced.Force = true
	forced.Logf = func(format string, args ...any) { logged = append(logged, fmt.Sprintf(format, args...)) }
	changed, err := Seal(forced, recipientsOf(a), f.plain, f.cipher)
	if err != nil || !changed {
		t.Fatalf("--force: changed=%v err=%v, want true", changed, err)
	}
	if len(logged) == 0 {
		t.Error("--force did not log a loud warning")
	}
}

func TestSealFirstEncryptNeedsNoIdentity(t *testing.T) {
	f := newFixture(t, "A=1\n")
	a := newParty(t)
	// No identity, no existing ciphertext → first encrypt is allowed.
	cfg := f.config(nil, fingerprintOf(a))
	changed, err := Seal(cfg, recipientsOf(a), f.plain, f.cipher)
	if err != nil || !changed {
		t.Fatalf("first encrypt: changed=%v err=%v, want true", changed, err)
	}
}

func TestOpenRejectsNonDotenvBeforeWriting(t *testing.T) {
	dir := t.TempDir()
	party := newParty(t)
	ciphertext, err := encryptBytes([]byte("this is not dotenv\nSECRET-VALUE"), []age.Recipient{party.rec})
	if err != nil {
		t.Fatal(err)
	}
	cipherPath := filepath.Join(dir, "bad.env.age")
	plainPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(cipherPath, ciphertext, 0o644); err != nil {
		t.Fatal(err)
	}
	err = Open(Config{Identities: []age.Identity{party.id}, Label: "test"}, cipherPath, plainPath)
	var invalid *InvalidDotenvError
	if !errors.As(err, &invalid) {
		t.Fatalf("Open error = %v, want InvalidDotenvError", err)
	}
	if _, statErr := os.Stat(plainPath); !os.IsNotExist(statErr) {
		t.Fatalf("plaintext was written for invalid dotenv payload: %v", statErr)
	}
	if strings.Contains(err.Error(), "SECRET-VALUE") {
		t.Fatalf("error leaked decrypted content: %v", err)
	}
}

// TestMergeSkewDetected reproduces the scenario that motivates the fingerprint:
// two teammates add a recipient on separate branches, recipients.toml merges to
// include both, but the ciphertext merge takes only one side. Nothing about the
// ciphertext bytes reveals this — only the lock fingerprint does. `check` (via
// VerifyLock) must fail.
func TestMergeSkewDetected(t *testing.T) {
	f := newFixture(t, "A=1\n")
	a, b, c := newParty(t), newParty(t), newParty(t)

	// Branch 1 added b and sealed to {a, b}: lock now records fp(a, b).
	cfg := f.config([]age.Identity{a.id}, fingerprintOf(a, b))
	if _, err := Seal(cfg, recipientsOf(a, b), f.plain, f.cipher); err != nil {
		t.Fatal(err)
	}

	// After the merge, recipients.toml is the union {a, b, c}, but the committed
	// ciphertext+lock are branch 1's (encrypted to {a, b} only).
	mergedFingerprint := fingerprintOf(a, b, c)

	// A naive check would pass — the ciphertext is valid and has stanzas. Only
	// the fingerprint catches the skew.
	targets := []LockTarget{{Ciphertext: filepath.Base(f.cipher), Path: f.cipher}}
	if err := VerifyLock(f.lock, targets, mergedFingerprint); err == nil {
		t.Fatal("VerifyLock passed on a merge-skewed repo; check would wrongly exit 0")
	} else if !strings.Contains(err.Error(), "out of sync") {
		t.Errorf("error = %v, want an out-of-sync message", err)
	}

	// And once someone re-encrypts to the union, check passes again.
	cfg2 := f.config([]age.Identity{a.id}, mergedFingerprint)
	if _, err := Seal(cfg2, recipientsOf(a, b, c), f.plain, f.cipher); err != nil {
		t.Fatal(err)
	}
	if err := VerifyLock(f.lock, targets, mergedFingerprint); err != nil {
		t.Errorf("VerifyLock failed after re-encrypt: %v", err)
	}
}

func TestDecryptDiagnosticsNeverExposeCiphertextOrPlaintext(t *testing.T) {
	const sentinel = "SENTINEL-SECRET-VALUE-DO-NOT-PRINT"
	p := newParty(t)

	if _, _, err := DecryptBytesToDotenv([]age.Identity{p.id}, []byte(sentinel)); err == nil {
		t.Fatal("expected malformed ciphertext error")
	} else if strings.Contains(err.Error(), sentinel) {
		t.Fatal("decryption diagnostic exposed ciphertext input")
	}

	ciphertext, err := encryptBytes([]byte(`TOKEN="safe" `+sentinel), []age.Recipient{p.rec})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := DecryptBytesToDotenv([]age.Identity{p.id}, ciphertext); err == nil {
		t.Fatal("expected malformed dotenv error")
	} else if strings.Contains(err.Error(), sentinel) {
		t.Fatal("decryption diagnostic exposed plaintext value")
	}
}

func TestSecretSafeErrorTypesAndSemanticComparison(t *testing.T) {
	invalid := &InvalidPlaintextError{Path: ".env", Err: errors.New("SENTINEL")}
	if strings.Contains(invalid.Error(), "SENTINEL") || !errors.Is(invalid, invalid.Err) {
		t.Fatal("InvalidPlaintextError did not preserve safe rendering and unwrapping")
	}
	identity := (&IdentityRequiredError{CiphertextPath: ".env.age", Reason: "identity unavailable"}).Error()
	divergence := (&DivergenceError{PlaintextPath: ".env", CiphertextPath: ".env.age"}).Error()
	if !strings.Contains(identity, "cannot verify") || !strings.Contains(divergence, "refusing to replace") {
		t.Fatal("planner error types omitted their safe remediation")
	}

	for _, pair := range [][2]string{
		{"A=1\n", "A=1\nB=2\n"},
		{"A=1\n", "B=1\n"},
		{"A=1\n", "A=2\n"},
		{"not dotenv", "A=1\n"},
	} {
		if sameContent([]byte(pair[0]), []byte(pair[1])) {
			t.Fatal("different dotenv inputs compared equal")
		}
	}
}
