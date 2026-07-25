// Package crypt is a thin wrapper over filippo.io/age. It owns the
// decrypt-compare-then-maybe-write loop that keeps ciphertext idempotent: no
// bytes are written unless the recipient set or the decrypted plaintext actually
// changed (CLAUDE.md rule 2).
package crypt

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"filippo.io/age"
	"filippo.io/age/armor"

	"github.com/YehiaGewily/envguardian/internal/atomic"
	"github.com/YehiaGewily/envguardian/internal/dotenv"
)

// ErrNotARecipient is returned by Open when the caller's identity cannot decrypt
// the file because it is not one of its recipients — the case a new teammate
// hits before someone adds them. It is reachable via errors.Is.
var ErrNotARecipient = errors.New("your key is not a recipient of this file")

// Config carries the shared inputs for Seal and Open.
type Config struct {
	// Identities decrypt the existing ciphertext for the compare step (Seal) or
	// for Open. Nil means "we can't decrypt".
	Identities []age.Identity
	// Label names the identity in messages (e.g. the source path).
	Label string
	// LockPath is .envguardian/lock.toml.
	LockPath string
	// Fingerprint is the current recipient-set fingerprint (public data only).
	Fingerprint string
	// Force re-encrypts even when the existing ciphertext can't be verified.
	Force bool
	// Logf receives loud warnings (e.g. blind --force writes). May be nil.
	Logf func(format string, args ...any)
}

func (c Config) logf(format string, args ...any) {
	if c.Logf != nil {
		c.Logf(format, args...)
	}
}

// Seal encrypts plaintextPath to recipients and writes ciphertextPath, but only
// when something actually changed. It returns whether it wrote.
//
// Policy when the existing ciphertext can't be decrypted (no identity, or ours
// isn't a recipient): error by default so we neither churn nor ship stale;
// --force re-encrypts blind, logging loudly.
func Seal(cfg Config, recipients []age.Recipient, plaintextPath, ciphertextPath string) (bool, error) {
	plaintext, err := os.ReadFile(plaintextPath) //nolint:gosec // G304: user-configured plaintext path
	if err != nil {
		return false, fmt.Errorf("read plaintext %s: %w", plaintextPath, err)
	}
	if _, err := dotenv.Parse(bytes.NewReader(plaintext)); err != nil {
		return false, fmt.Errorf("plaintext %s is not a valid .env: %w", plaintextPath, err)
	}

	lockFP, _ := readLockFingerprint(cfg.LockPath)
	recipientsChanged := lockFP != cfg.Fingerprint // missing/unparseable/mismatched → true

	_, statErr := os.Stat(ciphertextPath)
	cipherExists := statErr == nil

	// No ciphertext yet, or the recipient set changed (or the lock is unknown):
	// re-encrypt unconditionally and skip the decrypt-compare entirely.
	if !cipherExists || recipientsChanged {
		return cfg.writeSealed(plaintext, recipients, ciphertextPath)
	}

	// Recipients unchanged → we must decrypt to compare content.
	if len(cfg.Identities) == 0 {
		if cfg.Force {
			cfg.logf("WARNING: --force: re-encrypting %s without verifying it (no identity to decrypt-compare); writing blind", ciphertextPath)
			return cfg.writeSealed(plaintext, recipients, ciphertextPath)
		}
		return false, fmt.Errorf(
			"cannot verify %s is current: no available identity can decrypt it, so a rewrite can't be checked for idempotency — "+
				"supply an identity that is a recipient, or pass --force to re-encrypt blindly", ciphertextPath)
	}

	existing, err := os.ReadFile(ciphertextPath) //nolint:gosec // G304: user-configured ciphertext path
	if err != nil {
		return false, fmt.Errorf("read ciphertext %s: %w", ciphertextPath, err)
	}

	// Belt-and-braces: the header stanza count must match the recipient count.
	// Not a substitute for the fingerprint (3 recipients where 1 is wrong still
	// counts as 3), just a cheap free check.
	if n, err := stanzaCount(existing); err == nil && n != len(recipients) {
		return cfg.writeSealed(plaintext, recipients, ciphertextPath)
	}

	decrypted, err := decryptBytes(existing, cfg.Identities)
	if err != nil {
		if cfg.Force {
			cfg.logf("WARNING: --force: re-encrypting %s without verifying it (decrypt failed: %v); writing blind", ciphertextPath, err)
			return cfg.writeSealed(plaintext, recipients, ciphertextPath)
		}
		return false, fmt.Errorf("cannot decrypt existing %s to compare (pass --force to re-encrypt blindly): %w", ciphertextPath, err)
	}

	if sameContent(decrypted, plaintext) {
		return false, nil // idempotent: nothing changed, write nothing
	}
	return cfg.writeSealed(plaintext, recipients, ciphertextPath)
}

// writeSealed encrypts and writes both the ciphertext and the lock file.
func (c Config) writeSealed(plaintext []byte, recipients []age.Recipient, ciphertextPath string) (bool, error) {
	ct, err := encryptBytes(plaintext, recipients)
	if err != nil {
		return false, err
	}
	if err := atomic.WriteFile(ciphertextPath, ct, 0o644); err != nil {
		return false, err
	}
	if err := writeLock(c.LockPath, c.Fingerprint); err != nil {
		return false, fmt.Errorf("update lock file: %w", err)
	}
	return true, nil
}

// Open decrypts ciphertextPath to plaintextPath (mode 0600). When the identity
// is not a recipient it returns ErrNotARecipient with the fix.
func Open(cfg Config, ciphertextPath, plaintextPath string) error {
	ct, err := os.ReadFile(ciphertextPath) //nolint:gosec // G304: user-configured ciphertext path
	if err != nil {
		return fmt.Errorf("read ciphertext %s: %w", ciphertextPath, err)
	}
	plaintext, err := decryptBytes(ct, cfg.Identities)
	if err != nil {
		var nim *age.NoIdentityMatchError
		if errors.As(err, &nim) {
			return fmt.Errorf("%w\n  the identity used was: %s\n  fix: ask a teammate to run `envguardian add-recipient --github <username>` and commit the result",
				ErrNotARecipient, cfg.Label)
		}
		return fmt.Errorf("decrypt %s: %w", ciphertextPath, err)
	}
	if err := atomic.WriteFile(plaintextPath, plaintext, 0o600); err != nil {
		return err
	}
	return nil
}

func encryptBytes(plaintext []byte, recipients []age.Recipient) ([]byte, error) {
	var buf bytes.Buffer
	aw := armor.NewWriter(&buf)
	w, err := age.Encrypt(aw, recipients...)
	if err != nil {
		return nil, fmt.Errorf("start encryption: %w", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("finalize encryption: %w", err)
	}
	if err := aw.Close(); err != nil {
		return nil, fmt.Errorf("finalize armor: %w", err)
	}
	return buf.Bytes(), nil
}

func decryptBytes(raw []byte, identities []age.Identity) ([]byte, error) {
	var src io.Reader = bytes.NewReader(raw)
	if isArmored(raw) {
		src = armor.NewReader(src)
	}
	r, err := age.Decrypt(src, identities...)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

// stanzaCount returns the number of recipient stanzas in the age header.
func stanzaCount(raw []byte) (int, error) {
	var src io.Reader = bytes.NewReader(raw)
	if isArmored(raw) {
		src = armor.NewReader(src)
	}
	hdr, err := age.ExtractHeader(src)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, line := range bytes.Split(hdr, []byte("\n")) {
		if bytes.HasPrefix(line, []byte("-> ")) {
			n++
		}
	}
	return n, nil
}

// sameContent reports whether two .env blobs have identical key/value sets. A
// corrupt existing plaintext counts as changed so we re-encrypt.
func sameContent(existing, current []byte) bool {
	fe, err := dotenv.Parse(bytes.NewReader(existing))
	if err != nil {
		return false
	}
	fc, err := dotenv.Parse(bytes.NewReader(current))
	if err != nil {
		return false
	}
	if len(fe.Keys()) != len(fc.Keys()) {
		return false
	}
	for _, k := range fc.Keys() {
		ve, ok := fe.Get(k)
		if !ok {
			return false
		}
		vc, _ := fc.Get(k)
		if ve != vc {
			return false
		}
	}
	return true
}

func isArmored(b []byte) bool {
	return bytes.HasPrefix(bytes.TrimSpace(b), []byte(armor.Header))
}
