package crypt

import (
	"strings"
	"testing"
)

// FuzzParseLock asserts that parsing the committed lock never panics and that
// an accepted lock survives an encode→parse cycle with identical entries.
func FuzzParseLock(f *testing.F) {
	digest := strings.Repeat("ab", 32)
	for _, seed := range []string{
		"version = 2\n\n[[file]]\nciphertext = \".env.age\"\nrecipients_fingerprint = \"" + digest + "\"\nciphertext_sha256 = \"" + digest + "\"\n",
		"version = 1\n",
		"version = 2\n\n[[file]]\nciphertext = \".env.age\"\n",
		"version = 2\n\n[[file]]\nciphertext = \"a.age\"\nrecipients_fingerprint = \"zz\"\nciphertext_sha256 = \"zz\"\n",
		"",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		lock, err := parseLock(data)
		if err != nil {
			return
		}
		encoded, err := encodeLock(lock.Files)
		if err != nil {
			t.Fatalf("encodeLock accepted entries: %v", err)
		}
		again, err := parseLock(encoded)
		if err != nil {
			t.Fatalf("re-parse of encoded lock failed: %v", err)
		}
		if len(again.Files) != len(lock.Files) {
			t.Fatalf("entry count changed: %d then %d", len(lock.Files), len(again.Files))
		}
		for i := range lock.Files {
			if lock.Files[i] != again.Files[i] {
				t.Fatalf("lock entry %d changed across encode→parse", i)
			}
		}
	})
}
