// Package crypt is a thin wrapper over filippo.io/age. It owns the
// decrypt-compare-then-maybe-write loop that keeps ciphertext idempotent: no
// bytes are written unless the decrypted plaintext actually changed.
package crypt
