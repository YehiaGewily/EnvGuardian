package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/YehiaGewily/envguardian/internal/authenticity"
	"github.com/YehiaGewily/envguardian/internal/config"
	"github.com/YehiaGewily/envguardian/internal/crypt"
	"github.com/YehiaGewily/envguardian/internal/keys"
)

const unsignedMigrationWarning = "WARNING: ciphertext signature is missing; v0.1.x allows this only for migration, and v0.2 will reject it"

func signatureBinding(p config.Paths, fp config.FilePair, fingerprint string) (authenticity.Binding, error) {
	configRel, err := repoRelative(p.Root, p.Config)
	if err != nil {
		return authenticity.Binding{}, fmt.Errorf("resolve config path for ciphertext signature: %w", err)
	}
	return authenticity.Binding{
		RecipientsFingerprint: fingerprint,
		ConfigPath:            configRel,
		PlaintextPath:         fp.Plaintext,
		CiphertextPath:        fp.Ciphertext,
	}, nil
}

func finalCiphertext(plan *crypt.SealPlan) []byte {
	if plan.Changed {
		return plan.Replacement
	}
	return plan.Existing
}

// planCiphertextSignature preserves an already-valid current-recipient
// signature. Missing, stale, or invalid signatures are replaced before the
// transaction begins; no managed file is written here.
func planCiphertextSignature(p config.Paths, fp config.FilePair, fingerprint string, rf *keys.RecipientsFile, identity *keys.Identity, seal *crypt.SealPlan) (*crypt.FilePlan, error) {
	binding, err := signatureBinding(p, fp, fingerprint)
	if err != nil {
		return nil, err
	}
	ciphertext := finalCiphertext(seal)
	existing, readErr := os.ReadFile(fp.SignaturePath) //nolint:gosec // validated derived signature path
	if readErr == nil {
		if _, verifyErr := authenticity.Verify(existing, rf, binding, ciphertext); verifyErr == nil {
			return crypt.PlanFile(fp.SignaturePath, existing, 0o644)
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return nil, fmt.Errorf("read ciphertext signature %s: %w", authenticity.SignatureName(fp.Ciphertext), readErr)
	}
	signature, _, err := authenticity.Sign(identity, rf, binding, ciphertext)
	if err != nil {
		return nil, err
	}
	return crypt.PlanFile(fp.SignaturePath, signature, 0o644)
}

func verifyCiphertextSignature(p config.Paths, fp config.FilePair, rf *keys.RecipientsFile, ciphertext []byte) (signer string, missing bool, err error) {
	signature, readErr := os.ReadFile(fp.SignaturePath) //nolint:gosec // validated derived signature path
	if errors.Is(readErr, os.ErrNotExist) {
		return "", true, nil
	}
	if readErr != nil {
		return "", false, &authenticity.SignatureError{CiphertextPath: fp.Ciphertext, Reason: "read detached signature", Err: readErr}
	}
	binding, err := signatureBinding(p, fp, rf.Fingerprint())
	if err != nil {
		return "", false, err
	}
	signer, err = authenticity.Verify(signature, rf, binding, ciphertext)
	return signer, false, err
}
