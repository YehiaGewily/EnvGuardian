package rotation

import (
	"strings"
	"testing"
)

// FuzzParse asserts that parsing the public rotation ledger never panics and
// that an accepted ledger survives a Marshal→Parse cycle with the same key
// names.
func FuzzParse(f *testing.F) {
	for _, seed := range []string{
		"version = 1\n",
		"version = 1\n\n[[pending]]\nkey = \"STRIPE_SECRET_KEY\"\nrevoked = \"bob\"\nsince = \"2026-07-30\"\n",
		"version = 2\n",
		"version = 1\n\n[[pending]]\nkey = \"BAD KEY=value\"\n",
		"",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		ledger, err := Parse(data)
		if err != nil {
			return
		}
		encoded, err := ledger.Marshal()
		if err != nil {
			t.Fatalf("Marshal accepted ledger: %v", err)
		}
		again, err := Parse(encoded)
		if err != nil {
			t.Fatalf("re-parse of marshaled ledger failed: %v", err)
		}
		if strings.Join(ledger.Keys(), "\x00") != strings.Join(again.Keys(), "\x00") {
			t.Fatalf("pending key names changed: %v then %v", ledger.Keys(), again.Keys())
		}
	})
}
