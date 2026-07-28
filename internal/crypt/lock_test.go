package crypt

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyLockRejectsMalformedStructure(t *testing.T) {
	dir := t.TempDir()
	cipherPath := filepath.Join(dir, ".env.age")
	lockPath := filepath.Join(dir, "lock.toml")
	ciphertext := []byte("public-ciphertext")
	if err := os.WriteFile(cipherPath, ciphertext, 0o644); err != nil {
		t.Fatal(err)
	}
	fingerprint := "v1:" + strings.Repeat("a", 64)
	valid := LockEntry{Ciphertext: ".env.age", RecipientsFingerprint: fingerprint, CiphertextSHA256: ciphertextDigest(ciphertext)}
	targets := []LockTarget{{Ciphertext: ".env.age", Path: cipherPath}}

	tests := []struct {
		name string
		data []byte
		want string
	}{
		{name: "unsupported version", data: []byte("version = 1\n[[file]]\nciphertext = \".env.age\"\nrecipients_fingerprint = \"x\"\nciphertext_sha256 = \"" + strings.Repeat("0", 64) + "\"\n"), want: "unsupported lock version"},
		{name: "unknown field", data: []byte("version = 2\nunknown = true\n[[file]]\nciphertext = \".env.age\"\nrecipients_fingerprint = \"x\"\nciphertext_sha256 = \"" + strings.Repeat("0", 64) + "\"\n"), want: "unknown field"},
		{name: "malformed digest", data: []byte("version = 2\n[[file]]\nciphertext = \".env.age\"\nrecipients_fingerprint = \"x\"\nciphertext_sha256 = \"bad\"\n"), want: "malformed"},
		{name: "malformed fingerprint", data: []byte("version = 2\n[[file]]\nciphertext = \".env.age\"\nrecipients_fingerprint = \"bad\"\nciphertext_sha256 = \"" + strings.Repeat("0", 64) + "\"\n"), want: "malformed recipients_fingerprint"},
	}
	duplicate, err := encodeLock([]LockEntry{valid, valid})
	if err != nil {
		t.Fatal(err)
	}
	tests = append(tests, struct {
		name string
		data []byte
		want string
	}{name: "duplicate entry", data: duplicate, want: "duplicate lock entry"})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := os.WriteFile(lockPath, tt.data, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := VerifyLock(lockPath, targets, fingerprint); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}

	extra, err := encodeLock([]LockEntry{valid, {Ciphertext: "other.age", RecipientsFingerprint: fingerprint, CiphertextSHA256: ciphertextDigest(ciphertext)}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lockPath, extra, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := VerifyLock(lockPath, targets, fingerprint); err == nil || !strings.Contains(err.Error(), "has 2 entries") {
		t.Fatalf("extra-entry error = %v", err)
	}
}
