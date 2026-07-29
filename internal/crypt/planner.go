package crypt

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"filippo.io/age"

	"github.com/YehiaGewily/envguardian/internal/atomic"
	"github.com/YehiaGewily/envguardian/internal/dotenv"
)

// DivergenceError means local plaintext and committed ciphertext both contain
// different semantic dotenv content while recipient/lock state also requires
// a rewrite. Neither side is selected implicitly.
type DivergenceError struct {
	PlaintextPath  string
	CiphertextPath string
}

// IdentityRequiredError marks an existing ciphertext that cannot be safely
// planned without a usable decrypting identity.
type IdentityRequiredError struct {
	CiphertextPath string
	Reason         string
}

func (e *IdentityRequiredError) Error() string {
	return fmt.Sprintf("cannot verify existing %s: %s; supply an identity that is a recipient, or pass --force only for lost-key recovery", e.CiphertextPath, e.Reason)
}

func (e *DivergenceError) Error() string {
	return fmt.Sprintf(
		"refusing to replace %s: local %s differs from its decrypted content while recipient or lock state also changed; "+
			"decrypt to review the committed version, reconcile the plaintext explicitly, then encrypt again",
		e.CiphertextPath, e.PlaintextPath,
	)
}

// SealPlan retains all public ciphertext bytes needed to commit or roll back a
// planned seal. Replacement is generated before CommitSealPlans writes files.
type SealPlan struct {
	PlaintextPath  string
	CiphertextPath string
	Ciphertext     string
	Existing       []byte
	Replacement    []byte
	Changed        bool
	ExistingExists bool
}

// FilePlan is an additional public metadata write that participates in the
// same logical transaction as ciphertext and lock state (recipients.toml in
// v0.1.1).
type FilePlan struct {
	Path           string
	Existing       []byte
	Replacement    []byte
	Mode           os.FileMode
	Changed        bool
	ExistingExists bool
}

// CommitOptions supplies transaction metadata. Additional files are written
// after ciphertexts; the generated lock is always written last.
type CommitOptions struct {
	LockPath              string
	RecipientsFingerprint string
	Additional            []*FilePlan
}

// PlanFile snapshots a public metadata file and prepares a rollback-capable
// replacement without writing anything.
func PlanFile(path string, replacement []byte, mode os.FileMode) (*FilePlan, error) {
	existing, exists, err := readOptionalFile(path)
	if err != nil {
		return nil, fmt.Errorf("read existing %s: %w", path, err)
	}
	return &FilePlan{
		Path: path, Existing: existing, Replacement: append([]byte(nil), replacement...),
		Mode: mode, Changed: !exists || !bytes.Equal(existing, replacement), ExistingExists: exists,
	}, nil
}

// PlanSeal reads and validates plaintext and decrypts existing ciphertext
// before generating a replacement. It never writes. ciphertextName is the
// configured repository-relative name recorded in lock.toml.
func PlanSeal(cfg Config, recipients []age.Recipient, plaintextPath, ciphertextPath, ciphertextName string) (*SealPlan, error) {
	plan := &SealPlan{
		PlaintextPath: plaintextPath, CiphertextPath: ciphertextPath,
		Ciphertext: filepath.ToSlash(ciphertextName),
	}
	plaintext, plaintextExists, err := readOptionalFile(plaintextPath)
	if err != nil {
		return nil, fmt.Errorf("read plaintext %s: %w", plaintextPath, err)
	}
	if plaintextExists {
		if _, parseErr := dotenv.Parse(bytes.NewReader(plaintext)); parseErr != nil {
			return nil, &InvalidPlaintextError{Path: plaintextPath, Err: parseErr}
		}
	}

	existing, cipherExists, err := readOptionalFile(ciphertextPath)
	if err != nil {
		return nil, fmt.Errorf("read ciphertext %s: %w", ciphertextPath, err)
	}
	plan.Existing = existing
	plan.ExistingExists = cipherExists

	if !cipherExists {
		if !plaintextExists {
			return nil, fmt.Errorf("cannot create %s: plaintext %s does not exist", ciphertextPath, plaintextPath)
		}
		replacement, encryptErr := encryptBytes(plaintext, recipients)
		if encryptErr != nil {
			return nil, encryptErr
		}
		plan.Replacement = replacement
		plan.Changed = true
		return plan, nil
	}

	// Existing ciphertext is never replaced without decrypt-and-compare unless
	// the caller deliberately selected the loud lost-key --force escape hatch.
	if len(cfg.Identities) == 0 {
		return planBlind(cfg, recipients, plan, plaintext, plaintextExists, "no usable identity was found")
	}
	decrypted, _, decryptErr := DecryptBytesToDotenv(cfg.Identities, existing)
	if decryptErr != nil {
		if cfg.Force {
			return planBlind(cfg, recipients, plan, plaintext, plaintextExists, "the supplied identity could not decrypt the existing ciphertext")
		}
		return nil, fmt.Errorf("cannot decrypt existing %s to compare (pass --force only for lost-key recovery): %w", ciphertextPath, decryptErr)
	}

	lockCurrent := lockMatches(cfg.LockPath, plan.Ciphertext, cfg.Fingerprint, existing)
	semanticMatch := !plaintextExists || sameContent(decrypted, plaintext)
	if lockCurrent && semanticMatch {
		return plan, nil
	}
	if !lockCurrent && plaintextExists && !semanticMatch {
		return nil, &DivergenceError{PlaintextPath: plaintextPath, CiphertextPath: ciphertextPath}
	}

	// The existing decrypted bytes remain the source of truth for a recipient
	// or lock-only rewrite. Local plaintext is selected only for an ordinary
	// content change with already-current recipient/lock state.
	source := decrypted
	if lockCurrent && plaintextExists && !semanticMatch {
		source = plaintext
	}
	replacement, encryptErr := encryptBytes(source, recipients)
	if encryptErr != nil {
		return nil, encryptErr
	}
	plan.Replacement = replacement
	plan.Changed = true
	return plan, nil
}

func planBlind(cfg Config, recipients []age.Recipient, plan *SealPlan, plaintext []byte, plaintextExists bool, reason string) (*SealPlan, error) {
	if !cfg.Force {
		return nil, &IdentityRequiredError{CiphertextPath: plan.CiphertextPath, Reason: reason}
	}
	if !plaintextExists {
		return nil, fmt.Errorf("cannot --force replace %s without local plaintext %s", plan.CiphertextPath, plan.PlaintextPath)
	}
	cfg.logf("WARNING: --force: planning blind replacement of %s because %s", plan.CiphertextPath, reason)
	replacement, err := encryptBytes(plaintext, recipients)
	if err != nil {
		return nil, err
	}
	plan.Replacement = replacement
	plan.Changed = true
	return plan, nil
}

// CommitSealPlans atomically writes each planned file, writes lock.toml last,
// and rolls back already-attempted replacements on ordinary errors.
func CommitSealPlans(plans []*SealPlan, options CommitOptions) error {
	return commitSealPlans(plans, options, atomic.WriteFile)
}

type writeFileFunc func(string, []byte, os.FileMode) error

type mutation struct {
	path           string
	existing       []byte
	replacement    []byte
	mode           os.FileMode
	existingExists bool
}

func commitSealPlans(plans []*SealPlan, options CommitOptions, writeFile writeFileFunc) error {
	if len(plans) == 0 {
		return errors.New("no seal plans to commit")
	}
	if options.LockPath == "" {
		return errors.New("seal transaction has no lock path")
	}
	if !validFingerprint(options.RecipientsFingerprint) {
		return errors.New("seal transaction has a malformed recipient fingerprint")
	}
	entries := make([]LockEntry, 0, len(plans))
	mutations := make([]mutation, 0, len(plans)+len(options.Additional)+1)
	snapshots := make([]mutation, 0, len(plans)+len(options.Additional)+1)
	seenCiphertexts := make(map[string]struct{}, len(plans))
	seenPaths := make(map[string]struct{}, len(plans)+len(options.Additional)+1)
	anyChange := false
	for _, plan := range plans {
		if plan == nil {
			return errors.New("nil seal plan")
		}
		if _, duplicate := seenCiphertexts[plan.Ciphertext]; duplicate {
			return fmt.Errorf("duplicate seal plan for ciphertext %q", plan.Ciphertext)
		}
		if plan.Ciphertext == "" {
			return errors.New("seal plan has no configured ciphertext name")
		}
		seenCiphertexts[plan.Ciphertext] = struct{}{}
		cleanPath := filepath.Clean(plan.CiphertextPath)
		if _, duplicate := seenPaths[cleanPath]; duplicate {
			return fmt.Errorf("transaction contains duplicate destination %s", plan.CiphertextPath)
		}
		seenPaths[cleanPath] = struct{}{}
		snapshots = append(snapshots, mutation{path: plan.CiphertextPath, existing: plan.Existing, existingExists: plan.ExistingExists})
		finalBytes := plan.Existing
		if plan.Changed {
			if len(plan.Replacement) == 0 {
				return fmt.Errorf("changed seal plan for %s has no generated replacement", plan.Ciphertext)
			}
			finalBytes = plan.Replacement
			mutations = append(mutations, mutation{
				path: plan.CiphertextPath, existing: plan.Existing, replacement: plan.Replacement,
				mode: 0o644, existingExists: plan.ExistingExists,
			})
			anyChange = true
		}
		entries = append(entries, LockEntry{
			Ciphertext: plan.Ciphertext, RecipientsFingerprint: options.RecipientsFingerprint,
			CiphertextSHA256: ciphertextDigest(finalBytes),
		})
	}
	for _, extra := range options.Additional {
		if extra == nil {
			continue
		}
		clean := filepath.Clean(extra.Path)
		if _, duplicate := seenPaths[clean]; duplicate {
			return fmt.Errorf("transaction contains duplicate destination %s", extra.Path)
		}
		seenPaths[clean] = struct{}{}
		snapshots = append(snapshots, mutation{path: extra.Path, existing: extra.Existing, existingExists: extra.ExistingExists})
		if !extra.Changed {
			continue
		}
		mutations = append(mutations, mutation{
			path: extra.Path, existing: extra.Existing, replacement: extra.Replacement,
			mode: extra.Mode, existingExists: extra.ExistingExists,
		})
		anyChange = true
	}

	lockBytes, err := encodeLock(entries)
	if err != nil {
		return err
	}
	lockPlan, err := PlanFile(options.LockPath, lockBytes, 0o644)
	if err != nil {
		return err
	}
	if lockPlan.Changed {
		anyChange = true
	}
	if !anyChange {
		return nil
	}
	lockClean := filepath.Clean(options.LockPath)
	if _, duplicate := seenPaths[lockClean]; duplicate {
		return fmt.Errorf("lock path %s collides with another transaction destination", options.LockPath)
	}
	snapshots = append(snapshots, mutation{path: lockPlan.Path, existing: lockPlan.Existing, existingExists: lockPlan.ExistingExists})
	for _, snapshot := range snapshots {
		current, exists, readErr := readOptionalFile(snapshot.path)
		if readErr != nil {
			return fmt.Errorf("recheck transaction input %s: %w", snapshot.path, readErr)
		}
		if exists != snapshot.existingExists || (exists && !bytes.Equal(current, snapshot.existing)) {
			return fmt.Errorf("refusing stale transaction plan: %s changed after planning; retry the command", snapshot.path)
		}
	}
	// Lock is deliberately appended last so an interrupted earlier write is
	// detectable through its stale fingerprint or ciphertext digest.
	mutations = append(mutations, mutation{
		path: lockPlan.Path, existing: lockPlan.Existing, replacement: lockPlan.Replacement,
		mode: lockPlan.Mode, existingExists: lockPlan.ExistingExists,
	})

	applied := make([]mutation, 0, len(mutations))
	for _, item := range mutations {
		// Include the attempted item because Atomic.WriteFile can report a parent
		// fsync error after rename; rollback must assume the destination changed.
		applied = append(applied, item)
		if err := writeFile(item.path, item.replacement, item.mode); err != nil {
			rollbackErr := rollbackMutations(applied, writeFile)
			if rollbackErr != nil {
				return fmt.Errorf("commit transaction at %s: %w; rollback also failed: %v", item.path, err, rollbackErr)
			}
			return fmt.Errorf("commit transaction at %s: %w (all attempted writes rolled back)", item.path, err)
		}
	}
	return nil
}

func rollbackMutations(applied []mutation, writeFile writeFileFunc) error {
	var failures []error
	for i := len(applied) - 1; i >= 0; i-- {
		item := applied[i]
		if item.existingExists {
			if err := writeFile(item.path, item.existing, item.mode); err != nil {
				failures = append(failures, fmt.Errorf("restore %s: %w", item.path, err))
			}
			continue
		}
		if err := os.Remove(item.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			failures = append(failures, fmt.Errorf("remove new %s: %w", item.path, err))
		}
	}
	return errors.Join(failures...)
}

func readOptionalFile(path string) ([]byte, bool, error) {
	data, err := os.ReadFile(path) //nolint:gosec // caller supplies validated managed or metadata paths
	if err == nil {
		return data, true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	return nil, false, err
}

// Seal is the single-file compatibility wrapper. New command paths plan a
// slice first and call CommitSealPlans once.
func Seal(cfg Config, recipients []age.Recipient, plaintextPath, ciphertextPath string) (bool, error) {
	plan, err := PlanSeal(cfg, recipients, plaintextPath, ciphertextPath, filepath.Base(ciphertextPath))
	if err != nil {
		return false, err
	}
	if err := CommitSealPlans([]*SealPlan{plan}, CommitOptions{
		LockPath: cfg.LockPath, RecipientsFingerprint: cfg.Fingerprint,
	}); err != nil {
		return false, err
	}
	return plan.Changed, nil
}
