// Package crypt is a thin wrapper over filippo.io/age. It owns the
// decrypt-compare-plan-then-commit loop that keeps ciphertext idempotent and
// prevents recipient changes from selecting stale local plaintext.
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

// InvalidDotenvError identifies an invalid decrypted payload. Its rendered
// message deliberately omits the stored line and parser details because both
// are plaintext-derived and malformed trailing text can contain a secret.
type InvalidDotenvError struct {
	Line int
}

func (e *InvalidDotenvError) Error() string {
	return "decrypted payload is not valid dotenv; refusing to write plaintext"
}

// InvalidPlaintextError retains the parser error for programmatic inspection
// while rendering no plaintext-derived line number or malformed fragment.
type InvalidPlaintextError struct {
	Path string
	Err  error
}

func (e *InvalidPlaintextError) Error() string {
	return fmt.Sprintf("plaintext %s is not valid dotenv; refusing to encrypt", e.Path)
}

func (e *InvalidPlaintextError) Unwrap() error { return e.Err }

// DecryptError marks failures in the age decryption operation so the CLI can
// apply the documented identity/decrypt exit code without inspecting strings.
type DecryptError struct {
	Err error
}

func (e *DecryptError) Error() string {
	return "decrypt ciphertext: ciphertext is malformed, the identity does not match, or authentication failed"
}
func (e *DecryptError) Unwrap() error { return e.Err }

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

// Open decrypts ciphertextPath to plaintextPath (mode 0600). When the identity
// is not a recipient it returns ErrNotARecipient with the fix.
func Open(cfg Config, ciphertextPath, plaintextPath string) error {
	ct, err := os.ReadFile(ciphertextPath) //nolint:gosec // G304: user-configured ciphertext path
	if err != nil {
		return fmt.Errorf("read ciphertext %s: %w", ciphertextPath, err)
	}
	return OpenBytes(cfg, ct, plaintextPath)
}

// OpenBytes decrypts committed ciphertext bytes, validates the complete
// plaintext as dotenv, and only then atomically writes it with mode 0600.
func OpenBytes(cfg Config, ciphertext []byte, plaintextPath string) error {
	plaintext, _, err := DecryptBytesToDotenv(cfg.Identities, ciphertext)
	if err != nil {
		var nim *age.NoIdentityMatchError
		if errors.As(err, &nim) {
			return fmt.Errorf("%w\n  the identity used was: %s\n  fix: ask a teammate to run `envguardian add-recipient --github <username>` and commit the result",
				ErrNotARecipient, cfg.Label)
		}
		return &DecryptError{Err: err}
	}
	if err := atomic.WriteFile(plaintextPath, plaintext, 0o600); err != nil {
		return err
	}
	return nil
}

// DecryptBytesToDotenv decrypts and validates ciphertext entirely in memory.
// The plaintext return value is sensitive and must never be logged or persisted
// except through an approved 0600 plaintext destination.
func DecryptBytesToDotenv(identities []age.Identity, ciphertext []byte) ([]byte, *dotenv.File, error) {
	plaintext, err := decryptBytes(ciphertext, identities)
	if err != nil {
		return nil, nil, &DecryptError{Err: err}
	}
	f, err := dotenv.Parse(bytes.NewReader(plaintext))
	if err != nil {
		var parseErr *dotenv.ParseError
		if errors.As(err, &parseErr) {
			return nil, nil, &InvalidDotenvError{Line: parseErr.Line}
		}
		return nil, nil, &InvalidDotenvError{}
	}
	return plaintext, f, nil
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
