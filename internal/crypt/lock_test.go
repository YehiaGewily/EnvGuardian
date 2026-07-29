package crypt

import (
	"errors"
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

func TestVerifyLockBytesUsesExactSnapshot(t *testing.T) {
	fingerprint := "v1:" + strings.Repeat("b", 64)
	ciphertext := []byte("public-ciphertext-snapshot")
	lock, err := encodeLock([]LockEntry{{
		Ciphertext:            ".env.age",
		RecipientsFingerprint: fingerprint,
		CiphertextSHA256:      ciphertextDigest(ciphertext),
	}})
	if err != nil {
		t.Fatal(err)
	}
	targets := []LockBlobTarget{{Ciphertext: ".env.age", Data: ciphertext}}
	if err := VerifyLockBytes(lock, targets, fingerprint); err != nil {
		t.Fatalf("VerifyLockBytes valid snapshot: %v", err)
	}
	targets[0].Data = append(append([]byte(nil), ciphertext...), '\n')
	if err := VerifyLockBytes(lock, targets, fingerprint); err == nil || !strings.Contains(err.Error(), "does not match its lock digest") {
		t.Fatalf("VerifyLockBytes changed snapshot error=%v", err)
	}
}

func TestLockMatchesEntryInMultiFileLock(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "lock.toml")
	fingerprint := "v1:" + strings.Repeat("d", 64)
	first := []byte("first-public-ciphertext")
	second := []byte("second-public-ciphertext")
	data, err := encodeLock([]LockEntry{
		{Ciphertext: "first.age", RecipientsFingerprint: fingerprint, CiphertextSHA256: ciphertextDigest(first)},
		{Ciphertext: "second.age", RecipientsFingerprint: fingerprint, CiphertextSHA256: ciphertextDigest(second)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lockPath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if !lockMatches(lockPath, "second.age", fingerprint, second) {
		t.Fatal("lockMatches rejected a valid entry in a multi-file lock")
	}
	if lockMatches(lockPath, "second.age", fingerprint, append(second, '\n')) {
		t.Fatal("lockMatches accepted ciphertext bytes that differ from the lock digest")
	}
}

func TestLockVerificationFailureModes(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "lock.toml")
	fingerprint := "v1:" + strings.Repeat("c", 64)

	if err := VerifyLock(lockPath, nil, fingerprint); err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing lock error = %v", err)
	}
	if _, err := parseLock([]byte("version = 2\n")); err == nil || !strings.Contains(err.Error(), "no [[file]]") {
		t.Fatalf("empty lock error = %v", err)
	}
	missingName := []byte("version = 2\n[[file]]\nciphertext = \" \"\nrecipients_fingerprint = \"" + fingerprint + "\"\nciphertext_sha256 = \"" + strings.Repeat("0", 64) + "\"\n")
	if _, err := parseLock(missingName); err == nil || !strings.Contains(err.Error(), "has no ciphertext") {
		t.Fatalf("missing ciphertext name error = %v", err)
	}

	entries := []LockEntry{
		{Ciphertext: "a.age", RecipientsFingerprint: fingerprint, CiphertextSHA256: ciphertextDigest([]byte("a"))},
		{Ciphertext: "b.age", RecipientsFingerprint: fingerprint, CiphertextSHA256: ciphertextDigest([]byte("b"))},
	}
	lockData, err := encodeLock(entries)
	if err != nil {
		t.Fatal(err)
	}
	duplicateTargets := []LockBlobTarget{{Ciphertext: "a.age", Data: []byte("a")}, {Ciphertext: "a.age", Data: []byte("a")}}
	if err := VerifyLockBytes(lockData, duplicateTargets, fingerprint); err == nil || !strings.Contains(err.Error(), "more than once") {
		t.Fatalf("duplicate configured target error = %v", err)
	}
	wrongTargets := []LockBlobTarget{{Ciphertext: "other.age", Data: []byte("a")}, {Ciphertext: "b.age", Data: []byte("b")}}
	if err := VerifyLockBytes(lockData, wrongTargets, fingerprint); err == nil || !strings.Contains(err.Error(), "extra ciphertext") {
		t.Fatalf("extra lock entry error = %v", err)
	}
}
