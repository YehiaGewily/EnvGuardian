//go:build differential

// This file is compiled only with `-tags differential`. CI runs it explicitly
// as a separate conformance job. Run it locally with:
//
//	go test -tags differential ./internal/dotenv
//
// It parses every corpus input with both EnvGuardian and joho/godotenv and
// asserts that any divergence is one we deliberately documented in
// docs/dotenv-conformance.md. An *undocumented* divergence fails the test.

package dotenv

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/joho/godotenv"
)

var bomPrefix = string(rune(0xFEFF))

// corpusInputs is the full set of inputs the differential test runs over:
// testdata fixtures, the adversarial seeds, and any persisted fuzz corpus.
func corpusInputs(tb testing.TB) []string {
	tb.Helper()
	var out []string
	out = append(out, fixtureInputs(tb)...)
	out = append(out, adversarialSeeds...)
	out = append(out, persistedFuzzInputs(tb)...)
	return out
}

// persistedFuzzInputs decodes any inputs the fuzzer has saved under
// testdata/fuzz/FuzzParse/ (crashers and minimized regressions). The Go fuzz
// corpus format is a header line followed by one `string(...)` literal per
// argument; our fuzz target has a single string argument.
func persistedFuzzInputs(tb testing.TB) []string {
	tb.Helper()
	paths, err := filepath.Glob(filepath.Join("testdata", "fuzz", "FuzzParse", "*"))
	if err != nil || len(paths) == 0 {
		return nil
	}
	var out []string
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "string(") || !strings.HasSuffix(line, ")") {
				continue
			}
			if v, err := strconv.Unquote(strings.TrimSuffix(strings.TrimPrefix(line, "string("), ")")); err == nil {
				out = append(out, v)
			}
		}
	}
	return out
}

// TestDifferentialGodotenv is the conformance guard: our parser must agree with
// godotenv except where the conformance doc says otherwise.
func TestDifferentialGodotenv(t *testing.T) {
	for i, input := range corpusInputs(t) {
		t.Run(fmt.Sprintf("input_%02d", i), func(t *testing.T) {
			compareWithGodotenv(t, input)
		})
	}
}

func compareWithGodotenv(t *testing.T, input string) {
	t.Helper()

	ours, ourErr := Parse(strings.NewReader(input))
	theirs, theirErr := godotenv.Parse(strings.NewReader(input))

	switch {
	case ourErr != nil && theirErr != nil:
		// Both reject. Agreement — nothing more to check.
		return

	case ourErr != nil && theirErr == nil:
		// We are stricter. This is only allowed for a documented strict
		// rejection (conformance doc §3 rule 6 + "Why stricter than every
		// reference tool").
		if !isDocumentedStrictRejection(ourErr) {
			t.Fatalf("undocumented strict rejection: EnvGuardian error category %T; input and values omitted", ourErr)
		}
		return

	case ourErr == nil && theirErr != nil:
		// godotenv rejects but we accept. The only documented reason we tolerate
		// input godotenv chokes on is a leading BOM (doc case K): godotenv folds
		// the BOM into the first key so its line regex fails, while we strip it.
		if strings.HasPrefix(input, bomPrefix) {
			return
		}
		t.Fatalf("undocumented leniency: godotenv rejected input EnvGuardian accepted; values omitted")
		return

	default:
		// Both succeed — compare the resulting key/value maps.
		compareMaps(t, input, ours, theirs)
	}
}

func compareMaps(t *testing.T, input string, ours *File, theirs map[string]string) {
	t.Helper()

	hasBOM := strings.HasPrefix(input, bomPrefix)

	ourMap := make(map[string]string, len(ours.Keys()))
	for _, k := range ours.Keys() {
		v, _ := ours.Get(k)
		ourMap[k] = v
	}

	// Every key we produced must either match godotenv, or differ for a
	// documented reason.
	for k, ourVal := range ourMap {
		theirVal, ok := theirs[k]
		if !ok {
			// godotenv lacks a key we have. With a BOM, godotenv's first key is
			// BOM-prefixed (doc case K), so our clean key is "missing" for it.
			if hasBOM {
				continue
			}
			t.Fatalf("undocumented: key %q present for EnvGuardian but not godotenv; values omitted", k)
		}
		if ourVal != theirVal {
			raw := ours.nodes[ours.idx[k]].raw
			switch {
			case isEscapeDivergence(raw):
				// Case A: godotenv expands only \n and \r and drops other
				// backslashes; we expand the full \n \r \t \\ \" \$ set.
			case !utf8.ValidString(raw):
				// Case L: godotenv replaces invalid UTF-8 with U+FFFD; we
				// preserve the raw bytes.
			default:
				t.Fatalf("undocumented value divergence for key %q; values omitted", k)
			}
		}
	}

	// Keys godotenv produced that we don't — allowed only for the BOM-prefixed
	// first key.
	for k := range theirs {
		if _, ok := ourMap[k]; ok {
			continue
		}
		if hasBOM && strings.HasPrefix(k, bomPrefix) {
			continue
		}
		t.Fatalf("undocumented: key %q present for godotenv but not EnvGuardian; values omitted", k)
	}
}

// isEscapeDivergence reports whether the raw source for a key contains a
// double-quoted escape that EnvGuardian and godotenv handle differently
// (conformance doc case A). The escapes both tools agree on — \n \r \" \$ — do
// NOT trigger it, so a value mismatch on those still fails as a real bug. Any
// other backslash escape (\t, \\, \z, ...) is the documented divergence.
func isEscapeDivergence(raw string) bool {
	if !strings.Contains(raw, `"`) {
		return false
	}
	for i := 0; i+1 < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		switch raw[i+1] {
		case 'n', 'r', '"', '$':
			// Agreed-upon escapes; skip the escaped byte.
			i++
		default:
			return true
		}
	}
	return false
}

// isDocumentedStrictRejection reports whether err is one of the strict
// rejections EnvGuardian documents itself as making where lenient parsers would
// coerce or guess. Each maps to a case in docs/dotenv-conformance.md.
func isDocumentedStrictRejection(err error) bool {
	var pe *ParseError
	if !errors.As(err, &pe) {
		return false
	}
	documented := []string{
		"duplicate key",                    // case I
		"undefined variable",               // case C
		"missing '='",                      // case H (bare key)
		"missing variable name",            // grammar (rule 1)
		"start of key",                     // grammar (rule 1)
		"unterminated double-quoted value", // rule 6
		"unterminated single-quoted value", // rule 6
		"unterminated variable reference",  // rule 6
		"invalid variable name",            // rule 6
		"after closing quote",              // rule 6
	}
	for _, d := range documented {
		if strings.Contains(pe.Msg, d) {
			return true
		}
	}
	return false
}
