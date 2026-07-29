package crypt

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	atomicfile "github.com/YehiaGewily/envguardian/internal/atomic"
)

func readRequired(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func lockTargetsFor(f sealFixture) []LockTarget {
	return []LockTarget{{Ciphertext: filepath.Base(f.cipher), Path: f.cipher}}
}

func TestPlanSealRecipientMembershipChanges(t *testing.T) {
	tests := []struct {
		name       string
		initial    int
		next       func([]party, party) []party
		deniedOld  int
		allowedNew bool
	}{
		{name: "add recipient", initial: 1, next: func(old []party, added party) []party { return append(old, added) }, deniedOld: -1, allowedNew: true},
		{name: "replace key with same recipient count", initial: 2, next: func(old []party, added party) []party { return []party{old[0], added} }, deniedOld: 1, allowedNew: true},
		{name: "remove recipient", initial: 2, next: func(old []party, _ party) []party { return old[:1] }, deniedOld: 1, allowedNew: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t, "SECRET=current\n")
			all := []party{newParty(t), newParty(t)}
			initial := all[:tt.initial]
			initialCfg := f.config([]age.Identity{initial[0].id}, fingerprintOf(initial...))
			if _, err := Seal(initialCfg, recipientsOf(initial...), f.plain, f.cipher); err != nil {
				t.Fatal(err)
			}
			added := newParty(t)
			next := tt.next(initial, added)
			cfg := f.config([]age.Identity{initial[0].id}, fingerprintOf(next...))
			plan, err := PlanSeal(cfg, recipientsOf(next...), f.plain, f.cipher, filepath.Base(f.cipher))
			if err != nil {
				t.Fatalf("plan: %v", err)
			}
			if !plan.Changed {
				t.Fatal("recipient membership change did not force a replacement")
			}
			if err := CommitSealPlans([]*SealPlan{plan}, CommitOptions{LockPath: f.lock, RecipientsFingerprint: cfg.Fingerprint}); err != nil {
				t.Fatalf("commit: %v", err)
			}
			if err := VerifyLock(f.lock, lockTargetsFor(f), cfg.Fingerprint); err != nil {
				t.Fatalf("verify lock: %v", err)
			}
			if tt.allowedNew {
				out := filepath.Join(f.dir, "new-recipient.env")
				if err := Open(Config{Identities: []age.Identity{added.id}, Label: "new"}, f.cipher, out); err != nil {
					t.Fatalf("new recipient cannot decrypt: %v", err)
				}
			}
			if tt.deniedOld >= 0 {
				out := filepath.Join(f.dir, "removed-recipient.env")
				err := Open(Config{Identities: []age.Identity{initial[tt.deniedOld].id}, Label: "old"}, f.cipher, out)
				if !errors.Is(err, ErrNotARecipient) {
					t.Fatalf("removed/replaced identity error = %v, want ErrNotARecipient", err)
				}
			}
		})
	}
}

func TestPlanSealRejectsStalePlaintextDuringRecipientChange(t *testing.T) {
	f := newFixture(t, "DATABASE_URL=committed\n")
	a, b := newParty(t), newParty(t)
	initial := f.config([]age.Identity{a.id}, fingerprintOf(a))
	if _, err := Seal(initial, recipientsOf(a), f.plain, f.cipher); err != nil {
		t.Fatal(err)
	}
	beforeCipher := readRequired(t, f.cipher)
	beforeLock := readRequired(t, f.lock)
	if err := os.WriteFile(f.plain, []byte("DATABASE_URL=stale-branch\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	next := f.config([]age.Identity{a.id}, fingerprintOf(a, b))
	_, err := PlanSeal(next, recipientsOf(a, b), f.plain, f.cipher, filepath.Base(f.cipher))
	var conflict *DivergenceError
	if !errors.As(err, &conflict) {
		t.Fatalf("error = %v, want DivergenceError", err)
	}
	if !bytes.Equal(beforeCipher, readRequired(t, f.cipher)) || !bytes.Equal(beforeLock, readRequired(t, f.lock)) {
		t.Fatal("planning failure modified ciphertext or lock")
	}
}

func TestPlanSealMissingPlaintextUsesDecryptedCiphertext(t *testing.T) {
	f := newFixture(t, "A=committed\n")
	a, b := newParty(t), newParty(t)
	initial := f.config([]age.Identity{a.id}, fingerprintOf(a))
	if _, err := Seal(initial, recipientsOf(a), f.plain, f.cipher); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(f.plain); err != nil {
		t.Fatal(err)
	}
	next := f.config([]age.Identity{a.id}, fingerprintOf(a, b))
	plan, err := PlanSeal(next, recipientsOf(a, b), f.plain, f.cipher, filepath.Base(f.cipher))
	if err != nil || !plan.Changed {
		t.Fatalf("plan = changed %v, err %v", plan != nil && plan.Changed, err)
	}
	if _, err := os.Stat(f.plain); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("planning recreated plaintext: %v", err)
	}
}

func TestCommitSealPlansRollsBackOrdinaryFailure(t *testing.T) {
	f := newFixture(t, "A=1\n")
	a := newParty(t)
	cfg := f.config([]age.Identity{a.id}, fingerprintOf(a))
	if _, err := Seal(cfg, recipientsOf(a), f.plain, f.cipher); err != nil {
		t.Fatal(err)
	}
	beforeCipher := readRequired(t, f.cipher)
	beforeLock := readRequired(t, f.lock)
	if err := os.WriteFile(f.plain, []byte("A=2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	plan, err := PlanSeal(cfg, recipientsOf(a), f.plain, f.cipher, filepath.Base(f.cipher))
	if err != nil {
		t.Fatal(err)
	}
	failedOnce := false
	writer := func(path string, data []byte, mode os.FileMode) error {
		if filepath.Clean(path) == filepath.Clean(f.lock) && !failedOnce {
			failedOnce = true
			return fmt.Errorf("injected lock failure")
		}
		return atomicfile.WriteFile(path, data, mode)
	}
	err = commitSealPlans([]*SealPlan{plan}, CommitOptions{LockPath: f.lock, RecipientsFingerprint: cfg.Fingerprint}, writer)
	if err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("commit error = %v, want rollback report", err)
	}
	if !bytes.Equal(beforeCipher, readRequired(t, f.cipher)) || !bytes.Equal(beforeLock, readRequired(t, f.lock)) {
		t.Fatal("failed commit did not restore ciphertext and lock")
	}
}

func TestCommitSealPlansMultipleCiphertexts(t *testing.T) {
	dir := t.TempDir()
	alice := newParty(t)
	fingerprint := fingerprintOf(alice)
	lockPath := filepath.Join(dir, "lock.toml")
	cfg := Config{Identities: []age.Identity{alice.id}, LockPath: lockPath, Fingerprint: fingerprint, Label: "test"}
	recipients := recipientsOf(alice)

	type managed struct {
		plain  string
		cipher string
		name   string
	}
	files := []managed{
		{plain: filepath.Join(dir, "app.env"), cipher: filepath.Join(dir, "app.env.age"), name: "app.env.age"},
		{plain: filepath.Join(dir, "worker.env"), cipher: filepath.Join(dir, "worker.env.age"), name: "worker.env.age"},
	}
	for i, file := range files {
		if err := os.WriteFile(file.plain, []byte(fmt.Sprintf("VALUE=%d\n", i+1)), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	plans := make([]*SealPlan, 0, len(files))
	for _, file := range files {
		plan, err := PlanSeal(cfg, recipients, file.plain, file.cipher, file.name)
		if err != nil {
			t.Fatalf("plan %s: %v", file.name, err)
		}
		plans = append(plans, plan)
	}
	if err := CommitSealPlans(plans, CommitOptions{LockPath: lockPath, RecipientsFingerprint: fingerprint}); err != nil {
		t.Fatalf("commit multi-file plans: %v", err)
	}
	targets := make([]LockTarget, 0, len(files))
	for _, file := range files {
		targets = append(targets, LockTarget{Ciphertext: file.name, Path: file.cipher})
	}
	if err := VerifyLock(lockPath, targets, fingerprint); err != nil {
		t.Fatalf("verify multi-file lock: %v", err)
	}

	// Each plan must recognize its own entry in the shared lock, otherwise an
	// unchanged multi-file encrypt would churn randomized age ciphertext.
	for _, file := range files {
		plan, err := PlanSeal(cfg, recipients, file.plain, file.cipher, file.name)
		if err != nil {
			t.Fatalf("replan %s: %v", file.name, err)
		}
		if plan.Changed {
			t.Fatalf("unchanged multi-file plan %s requested a rewrite", file.name)
		}
	}
}

func TestCommitSealPlansRollsBackAdditionalMetadata(t *testing.T) {
	f := newFixture(t, "A=1\n")
	a, b := newParty(t), newParty(t)
	initial := f.config([]age.Identity{a.id}, fingerprintOf(a))
	if _, err := Seal(initial, recipientsOf(a), f.plain, f.cipher); err != nil {
		t.Fatal(err)
	}
	metadataPath := filepath.Join(f.dir, "recipients.toml")
	if err := os.WriteFile(metadataPath, []byte("old-public-metadata\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	beforeCipher := readRequired(t, f.cipher)
	beforeLock := readRequired(t, f.lock)
	beforeMetadata := readRequired(t, metadataPath)
	next := f.config([]age.Identity{a.id}, fingerprintOf(a, b))
	plan, err := PlanSeal(next, recipientsOf(a, b), f.plain, f.cipher, filepath.Base(f.cipher))
	if err != nil {
		t.Fatal(err)
	}
	metadataPlan, err := PlanFile(metadataPath, []byte("new-public-metadata\n"), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	failedOnce := false
	writer := func(path string, data []byte, mode os.FileMode) error {
		if filepath.Clean(path) == filepath.Clean(f.lock) && !failedOnce {
			failedOnce = true
			return fmt.Errorf("injected lock failure")
		}
		return atomicfile.WriteFile(path, data, mode)
	}
	err = commitSealPlans([]*SealPlan{plan}, CommitOptions{
		LockPath: f.lock, RecipientsFingerprint: next.Fingerprint, Additional: []*FilePlan{metadataPlan},
	}, writer)
	if err == nil {
		t.Fatal("expected injected commit failure")
	}
	if !bytes.Equal(beforeCipher, readRequired(t, f.cipher)) ||
		!bytes.Equal(beforeLock, readRequired(t, f.lock)) ||
		!bytes.Equal(beforeMetadata, readRequired(t, metadataPath)) {
		t.Fatal("rollback did not restore ciphertext, lock, and additional metadata")
	}
}

func TestVerifyLockDetectsInterruptedCiphertextCommit(t *testing.T) {
	f := newFixture(t, "A=1\n")
	a := newParty(t)
	cfg := f.config([]age.Identity{a.id}, fingerprintOf(a))
	if _, err := Seal(cfg, recipientsOf(a), f.plain, f.cipher); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.plain, []byte("A=2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	plan, err := PlanSeal(cfg, recipientsOf(a), f.plain, f.cipher, filepath.Base(f.cipher))
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a crash after ciphertext rename but before the lock-last write.
	if err := atomicfile.WriteFile(f.cipher, plan.Replacement, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := VerifyLock(f.lock, lockTargetsFor(f), cfg.Fingerprint); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("VerifyLock error = %v, want digest mismatch", err)
	}
}

func TestPlanningReadFailuresWriteNothing(t *testing.T) {
	dir := t.TempDir()
	if _, err := PlanFile(dir, []byte("public metadata"), 0o644); err == nil {
		t.Fatal("PlanFile accepted a directory as an existing file")
	}
	alice := newParty(t)
	cipherPath := filepath.Join(dir, ".env.age")
	cfg := Config{Fingerprint: fingerprintOf(alice)}
	if _, err := PlanSeal(cfg, recipientsOf(alice), dir, cipherPath, ".env.age"); err == nil {
		t.Fatal("PlanSeal accepted a directory as plaintext")
	}
	if _, err := os.Stat(cipherPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("planning failure wrote ciphertext")
	}
}

func TestPlanSealResolvedContentBranches(t *testing.T) {
	t.Run("new ciphertext", func(t *testing.T) {
		dir := t.TempDir()
		alice := newParty(t)
		path := filepath.Join(dir, "new.age")
		plan, err := PlanSealResolvedContent(Config{Fingerprint: fingerprintOf(alice)}, recipientsOf(alice), []byte("A=1\n"), path, "new.age")
		if err != nil || !plan.Changed || plan.ExistingExists {
			t.Fatalf("new resolved plan = %+v, %v", plan, err)
		}
		if err := CommitMergeCiphertext(plan); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("unchanged and changed", func(t *testing.T) {
		f := newFixture(t, "A=base\n")
		alice := newParty(t)
		cfg := f.config([]age.Identity{alice.id}, fingerprintOf(alice))
		if _, err := Seal(cfg, recipientsOf(alice), f.plain, f.cipher); err != nil {
			t.Fatal(err)
		}
		unchanged, err := PlanSealResolvedContent(cfg, recipientsOf(alice), []byte("# reordered formatting\nA=base\n"), f.cipher, filepath.Base(f.cipher))
		if err != nil || unchanged.Changed {
			t.Fatalf("unchanged resolved plan = %+v, %v", unchanged, err)
		}
		changed, err := PlanSealResolvedContent(cfg, recipientsOf(alice), []byte("A=merged\n"), f.cipher, filepath.Base(f.cipher))
		if err != nil || !changed.Changed {
			t.Fatalf("changed resolved plan = %+v, %v", changed, err)
		}
		if err := CommitMergeCiphertext(changed); err != nil {
			t.Fatal(err)
		}
		plaintext, file, err := DecryptBytesToDotenv([]age.Identity{alice.id}, readRequired(t, f.cipher))
		if err != nil || file == nil || string(plaintext) != "A=merged\n" {
			t.Fatalf("merged ciphertext content was not committed: %v", err)
		}
	})

	t.Run("recipient change forces rewrite", func(t *testing.T) {
		f := newFixture(t, "A=base\n")
		alice, bob := newParty(t), newParty(t)
		initial := f.config([]age.Identity{alice.id}, fingerprintOf(alice))
		if _, err := Seal(initial, recipientsOf(alice), f.plain, f.cipher); err != nil {
			t.Fatal(err)
		}
		next := f.config([]age.Identity{alice.id}, fingerprintOf(alice, bob))
		plan, err := PlanSealResolvedContent(next, recipientsOf(alice, bob), []byte("A=base\n"), f.cipher, filepath.Base(f.cipher))
		if err != nil || !plan.Changed {
			t.Fatalf("recipient-change plan = %+v, %v", plan, err)
		}
	})
}

func TestPlanSealResolvedContentFailures(t *testing.T) {
	alice, wrong := newParty(t), newParty(t)
	f := newFixture(t, "A=base\n")
	cfg := f.config([]age.Identity{alice.id}, fingerprintOf(alice))
	if _, err := Seal(cfg, recipientsOf(alice), f.plain, f.cipher); err != nil {
		t.Fatal(err)
	}
	if _, err := PlanSealResolvedContent(cfg, recipientsOf(alice), []byte("not dotenv"), f.cipher, ".env.age"); err == nil {
		t.Fatal("invalid resolved dotenv was accepted")
	}
	if _, err := PlanSealResolvedContent(Config{Fingerprint: cfg.Fingerprint, LockPath: f.lock}, recipientsOf(alice), []byte("A=next\n"), f.cipher, ".env.age"); err == nil {
		t.Fatal("existing ciphertext was accepted without an identity")
	}
	if _, err := PlanSealResolvedContent(Config{Identities: []age.Identity{wrong.id}, Fingerprint: cfg.Fingerprint, LockPath: f.lock}, recipientsOf(alice), []byte("A=next\n"), f.cipher, ".env.age"); err == nil {
		t.Fatal("undecryptable existing ciphertext was accepted")
	}
}

func TestCommitMergeCiphertextRejectsInvalidAndStalePlans(t *testing.T) {
	if err := CommitMergeCiphertext(nil); err == nil {
		t.Fatal("nil merge plan was accepted")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "cipher.age")
	if err := os.WriteFile(path, []byte("before"), 0o644); err != nil {
		t.Fatal(err)
	}
	plan := &SealPlan{
		CiphertextPath: path, Existing: []byte("before"), ExistingExists: true,
		Replacement: []byte("after"), Changed: true,
	}
	if err := os.WriteFile(path, []byte("raced"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := CommitMergeCiphertext(plan); err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("stale merge plan error = %v", err)
	}
}
