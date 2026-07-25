package dotenv

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// adversarialSeeds are hand-picked inputs that stress the parser's edges. They
// seed the fuzzer and feed the differential test.
var adversarialSeeds = []string{
	`A="unterminated`,
	`B='unterminated`,
	`C=${UNCLOSED`,
	"HUGE=" + strings.Repeat("x", 50_000),
	strings.Repeat("K", 50_000) + "=v",
	"NUL=\x00\x00\x00",
	"BAD=\xff\xfe\xfd",     // invalid UTF-8
	"NESTED=${${VAR}}",     // deeply nested interpolation
	"DEEP=${${${${X}}}}",   //
	"A=1\r\nB=2\n\rC=3",    // mixed line endings
	"\xEF\xBB\xBFX=1",      // BOM
	"=noname",              // missing key
	"export ",              // dangling export
	"# just a comment",     //
	"A=1\nA=2",             // duplicate
	"K=a\\$b\\\\c\\\"d",    // escape soup
	"multi=\"a\nb\nc\"",    // multiline
	"\n\n\n\n",             // all blank
	"K==",                  // empty-ish
	"日本語=value",            // non-ASCII key bytes
	"FOO=bar # comment",    // inline comment (space)
	"FOO=sec#ret",          // hash mid-value (no space)
	"URL=http://h/#frag",   // hash after slash
	"HOST=db\nURL=${HOST}", // interpolation
	"S='${HOST}'",          // interpolation suppressed in single quotes
	"export TOKEN=abc",     // export prefix
	"K = spaced ",          // whitespace around =
	"EMPTY=",               // empty value
	"Q=\"a\\tb\"",          // escape expansion
}

// fixtureInputs returns the raw contents of every testdata/*.env fixture.
func fixtureInputs(tb testing.TB) []string {
	tb.Helper()
	paths, err := filepath.Glob(filepath.Join("testdata", "*.env"))
	if err != nil {
		tb.Fatal(err)
	}
	var out []string
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			tb.Fatal(err)
		}
		out = append(out, string(data))
	}
	return out
}
