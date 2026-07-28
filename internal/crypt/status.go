package crypt

import (
	"errors"
	"os"

	"filippo.io/age"

	"github.com/YehiaGewily/envguardian/internal/dotenv"
)

// Status describes an encrypted file relative to its plaintext. It is what
// `check` and the pre-commit hook use to decide whether things are in sync.
type Status struct {
	CiphertextExists bool
	PlaintextExists  bool
	Decryptable      bool // the given identities can decrypt the ciphertext
	Matches          bool // decrypted content equals the plaintext (key/value set)
}

// Inspect reports the relationship between a ciphertext and its plaintext using
// the given identities. A file that simply isn't decryptable by these
// identities is reported as Decryptable=false with no error; only IO or
// corruption problems return an error.
func Inspect(identities []age.Identity, ciphertextPath, plaintextPath string) (Status, error) {
	var s Status

	ct, err := os.ReadFile(ciphertextPath) //nolint:gosec // G304: user-configured ciphertext path
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil // CiphertextExists stays false
		}
		return s, err
	}
	s.CiphertextExists = true

	plain, perr := os.ReadFile(plaintextPath) //nolint:gosec // G304: user-configured plaintext path
	switch {
	case perr == nil:
		s.PlaintextExists = true
	case !os.IsNotExist(perr):
		return s, perr
	}

	if len(identities) > 0 {
		dec, derr := decryptBytes(ct, identities)
		if derr == nil {
			s.Decryptable = true
			if s.PlaintextExists {
				s.Matches = sameContent(dec, plain)
			}
		} else {
			var nim *age.NoIdentityMatchError
			if !errors.As(derr, &nim) {
				return s, derr // corrupt/unreadable ciphertext
			}
			// Not a recipient: Decryptable stays false, not an error.
		}
	}
	return s, nil
}

// DecryptToDotenv decrypts a ciphertext file and parses it. The returned File's
// values are for in-process use only (e.g. the diff command's change
// detection); callers must never emit them or any derivative of them.
func DecryptToDotenv(identities []age.Identity, ciphertextPath string) (*dotenv.File, error) {
	ct, err := os.ReadFile(ciphertextPath) //nolint:gosec // G304: user-configured ciphertext path
	if err != nil {
		return nil, err
	}
	_, f, err := DecryptBytesToDotenv(identities, ct)
	return f, err
}
