package dotenv

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRoundTripFixtures is the critical property: parse-then-write of an
// unmodified file is byte-identical to the input, for every fixture (which
// between them cover multiline PEM values, CRLF endings, and a leading BOM).
func TestRoundTripFixtures(t *testing.T) {
	matches, err := filepath.Glob(filepath.Join("testdata", "*.env"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 {
		t.Fatal("no testdata fixtures found")
	}
	for _, path := range matches {
		t.Run(filepath.Base(path), func(t *testing.T) {
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			f, err := Parse(bytes.NewReader(want))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			var got bytes.Buffer
			if _, err := f.WriteTo(&got); err != nil {
				t.Fatalf("WriteTo: %v", err)
			}
			if !bytes.Equal(got.Bytes(), want) {
				t.Errorf("round-trip not byte-identical\n got: %q\nwant: %q", got.Bytes(), want)
			}
		})
	}
}

// TestRoundTripSynthetic covers formatting quirks not in the fixtures: no
// trailing newline, odd spacing, blank lines, inline comments.
func TestRoundTripSynthetic(t *testing.T) {
	inputs := []string{
		"A=1\nB=2\n",
		"A=1\nB=2",             // no trailing newline
		"",                     // empty
		"\n",                   // single blank line
		"# comment only\n",     // comment, trailing newline
		"K =   spaced   # c\n", // preserved spacing + inline comment
		"export FOO=bar\n",
		"A='literal $x #y'\n",
		"\n\n# mid\n\nX=1\n",
	}
	for _, in := range inputs {
		f, err := Parse(strings.NewReader(in))
		if err != nil {
			t.Fatalf("Parse(%q): %v", in, err)
		}
		var got bytes.Buffer
		if _, err := f.WriteTo(&got); err != nil {
			t.Fatalf("WriteTo(%q): %v", in, err)
		}
		if got.String() != in {
			t.Errorf("round-trip mismatch\n  in: %q\n out: %q", in, got.String())
		}
	}
}

func TestWriteNewKeyAppended(t *testing.T) {
	f, err := Parse(strings.NewReader("A=1\nB=2\n"))
	if err != nil {
		t.Fatal(err)
	}
	f.Set("C", "3")
	var got bytes.Buffer
	if _, err := f.WriteTo(&got); err != nil {
		t.Fatal(err)
	}
	want := "A=1\nB=2\nC=3\n"
	if got.String() != want {
		t.Errorf("WriteTo = %q, want %q", got.String(), want)
	}
}

// TestWriteRerenderQuoting checks that Set values which need quoting come back
// out in a form that re-parses to the same value.
func TestWriteRerenderQuoting(t *testing.T) {
	cases := []struct {
		key, value, wantLine string
	}{
		{"PLAIN", "simple", "PLAIN=simple"},
		{"SPACED", "a b c", "SPACED='a b c'"},
		{"HASH", "a #b", "HASH='a #b'"},
		{"DOLLAR", "$HOME", "DOLLAR='$HOME'"},
		{"QUOTED", "he said 'hi'", `QUOTED="he said 'hi'"`},
		{"NEWLINE", "a\nb", `NEWLINE="a\nb"`},
		{"EMPTY", "", "EMPTY="},
	}
	for _, c := range cases {
		t.Run(c.key, func(t *testing.T) {
			f, err := Parse(strings.NewReader(""))
			if err != nil {
				t.Fatal(err)
			}
			f.Set(c.key, c.value)
			var got bytes.Buffer
			if _, err := f.WriteTo(&got); err != nil {
				t.Fatal(err)
			}
			if strings.TrimRight(got.String(), "\n") != c.wantLine {
				t.Errorf("rendered %q, want %q", got.String(), c.wantLine)
			}
			// And it must re-parse to the original value.
			f2, err := Parse(strings.NewReader(got.String()))
			if err != nil {
				t.Fatalf("re-parse failed: %v", err)
			}
			if v, _ := f2.Get(c.key); v != c.value {
				t.Errorf("re-parsed %q = %q, want %q", c.key, v, c.value)
			}
		})
	}
}
