package dotenv

import (
	"bytes"
	"strings"
	"testing"
)

// FuzzParse asserts two properties:
//  1. Parse never panics on any input.
//  2. When Parse succeeds, the file survives a WriteTo→Parse→WriteTo cycle
//     unchanged (the serializer is a stable fixpoint and never emits something
//     it cannot read back).
func FuzzParse(f *testing.F) {
	// Seed from the shared corpus: fixtures + adversarial inputs.
	for _, s := range fixtureInputs(f) {
		f.Add(s)
	}
	for _, s := range adversarialSeeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, input string) {
		f1, err := Parse(strings.NewReader(input))
		if err != nil {
			return // rejecting malformed input is fine; it just must not panic.
		}

		var out1 bytes.Buffer
		if _, err := f1.WriteTo(&out1); err != nil {
			t.Fatalf("WriteTo failed on a successfully parsed file: %v", err)
		}

		// Anything we wrote must parse back.
		f2, err := Parse(bytes.NewReader(out1.Bytes()))
		if err != nil {
			t.Fatalf("re-parse of serialized output failed: %T; input and output omitted", err)
		}

		// The serializer must be a fixpoint.
		var out2 bytes.Buffer
		if _, err := f2.WriteTo(&out2); err != nil {
			t.Fatalf("second WriteTo failed: %v", err)
		}
		if !bytes.Equal(out1.Bytes(), out2.Bytes()) {
			t.Fatal("serialization not stable; outputs omitted")
		}

		// Keys and values must be preserved across the cycle.
		k1, k2 := f1.Keys(), f2.Keys()
		if strings.Join(k1, "\x00") != strings.Join(k2, "\x00") {
			t.Fatalf("keys diverged: %v vs %v; input omitted", k1, k2)
		}
		for _, k := range k1 {
			v1, _ := f1.Get(k)
			v2, _ := f2.Get(k)
			if v1 != v2 {
				t.Fatalf("value for %q diverged; values and input omitted", k)
			}
		}
	})
}
