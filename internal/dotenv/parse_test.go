package dotenv

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func parse(t *testing.T, s string) *File {
	t.Helper()
	f, err := Parse(strings.NewReader(s))
	if err != nil {
		t.Fatalf("Parse(%q) unexpected error: %v", s, err)
	}
	return f
}

// entryNode returns the internal node for a key so tests can inspect quote
// style, inline comment, line number, and the export prefix.
func entryNode(t *testing.T, f *File, key string) node {
	t.Helper()
	i, ok := f.idx[key]
	if !ok {
		t.Fatalf("key %q not found; have %v", key, f.Keys())
	}
	return f.nodes[i]
}

// TestValues walks every row of docs/dotenv-conformance.md, including the cases
// where EnvGuardian deliberately diverges from one or more reference tools.
func TestValues(t *testing.T) {
	tests := []struct {
		name  string
		input string
		key   string
		want  string
	}{
		// A — double-quote escapes: full set expands.
		{"double_escapes", `A="line1\nline2\ttab"`, "A", "line1\nline2\ttab"},
		{"double_all_escapes", `A="a\tb\\c\"d\$e"`, "A", "a\tb\\c\"d$e"},
		// B — single quotes are fully literal.
		{"single_literal", `B='line1\nline2 ${HOST} #x'`, "B", `line1\nline2 ${HOST} #x`},
		// C — interpolation in unquoted and double-quoted values.
		{"interp_unquoted", "HOST=db.local\nC=postgres://${HOST}:5432", "C", "postgres://db.local:5432"},
		{"interp_double", "HOST=db.local\nC=\"postgres://${HOST}:5432\"", "C", "postgres://db.local:5432"},
		{"interp_bare_dollar", "HOST=db.local\nC=$HOST/db", "C", "db.local/db"},
		{"interp_chained", "A=1\nB=${A}2\nC=${B}3", "C", "123"},
		// C — but NOT inside single quotes.
		{"interp_single_suppressed", "HOST=db.local\nS='${HOST}'", "S", "${HOST}"},
		// C — escaped dollar stays literal even when the var exists.
		{"escaped_dollar", "HOST=x\nK=\"\\$HOST\"", "K", "$HOST"},
		{"literal_dollar_price", "K=$5.00", "K", "$5.00"},
		// E — export prefix stripped from the key.
		{"export_prefix", "export TOKEN=abc", "TOKEN", "abc"},
		// F — inline comment requires a leading space; '#' mid-value is literal.
		{"inline_comment", "F1=secret # prod key", "F1", "secret"},
		{"hash_in_value", "F2=sec#ret", "F2", "sec#ret"},
		{"url_fragment", "U=http://h/#frag", "U", "http://h/#frag"},
		{"hash_first_char", "K=#c", "K", "#c"},
		{"comment_empty_value", "K= # c", "K", ""},
		// G — whitespace around '=' is trimmed.
		{"ws_around_equals", "K = v", "K", "v"},
		{"ws_trimmed_unquoted", "K=   v   ", "K", "v"},
		{"ws_kept_in_quotes", `K="  v  "`, "K", "  v  "},
		// H — empty value is valid.
		{"empty_value", "E=", "E", ""},
		// double-quoted comment after the closing quote.
		{"double_then_comment", `K="a b" # note`, "K", "a b"},
		{"double_comment_no_space", `K="v"#c`, "K", "v"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := parse(t, tt.input)
			got, ok := f.Get(tt.key)
			if !ok {
				t.Fatalf("Get(%q) missing; keys=%v", tt.key, f.Keys())
			}
			if got != tt.want {
				t.Errorf("Get(%q) = %q, want %q", tt.key, got, tt.want)
			}
		})
	}
}

func TestEntryMetadata(t *testing.T) {
	f := parse(t, "# header\nexport TOKEN=abc # secret token\nPLAIN='x'")

	tok := entryNode(t, f, "TOKEN")
	if !tok.export {
		t.Error("TOKEN: export prefix not recorded")
	}
	if tok.entry.Quote != QuoteNone {
		t.Errorf("TOKEN: quote = %v, want none", tok.entry.Quote)
	}
	if tok.entry.Comment != "secret token" {
		t.Errorf("TOKEN: comment = %q, want %q", tok.entry.Comment, "secret token")
	}
	if tok.entry.Line != 2 {
		t.Errorf("TOKEN: line = %d, want 2", tok.entry.Line)
	}

	plain := entryNode(t, f, "PLAIN")
	if plain.entry.Quote != QuoteSingle {
		t.Errorf("PLAIN: quote = %v, want single", plain.entry.Quote)
	}
	if plain.entry.Line != 3 {
		t.Errorf("PLAIN: line = %d, want 3", plain.entry.Line)
	}
}

func TestErrors(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantLine int
		wantSub  string
	}{
		{"bare_key", "FOO\nBAR=1", 1, "missing '='"},
		{"missing_name", "=value", 1, "missing variable name"},
		{"bad_key_start", "1KEY=v", 1, "start of key"},
		{"duplicate", "D=1\nD=2", 2, "duplicate key"},
		{"duplicate_reports_first", "D=1\nX=2\nD=3", 3, "line 1"},
		{"undefined_var", "K=${MISSING}", 1, "undefined variable"},
		{"undefined_bare", "K=$MISSING/x", 1, "undefined variable"},
		{"unterminated_double", "K=\"abc", 1, "unterminated double"},
		{"unterminated_single", "K='abc", 1, "unterminated single"},
		{"unterminated_brace", "A=1\nK=${A", 2, "unterminated variable reference"},
		{"junk_after_quote", `K="v" junk`, 1, "after closing quote"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(strings.NewReader(tt.input))
			if err == nil {
				t.Fatalf("Parse(%q) = nil error, want error", tt.input)
			}
			var pe *ParseError
			if !errors.As(err, &pe) {
				t.Fatalf("error type = %T, want *ParseError", err)
			}
			if pe.Line != tt.wantLine {
				t.Errorf("line = %d, want %d (err: %v)", pe.Line, tt.wantLine, err)
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantSub)
			}
			if pe.Hint == "" {
				t.Errorf("error for %q carries no fix hint", tt.name)
			}
		})
	}
}

func TestParseErrorsNeverExposeValueText(t *testing.T) {
	const sentinel = "SENTINEL-SECRET-VALUE-DO-NOT-PRINT"
	inputs := []string{
		`TOKEN="safe" ` + sentinel,
		`TOKEN="` + sentinel,
		`TOKEN='` + sentinel,
	}
	for i, input := range inputs {
		_, err := Parse(strings.NewReader(input))
		if err == nil {
			t.Fatalf("case %d: expected malformed dotenv error", i)
		}
		if strings.Contains(err.Error(), sentinel) {
			t.Fatalf("case %d: malformed dotenv error exposed value text", i)
		}
	}
}

func TestMultilinePEM(t *testing.T) {
	f := readFixture(t, "pem.env")

	key, ok := f.Get("TLS_KEY")
	if !ok {
		t.Fatal("TLS_KEY missing")
	}
	if !strings.HasPrefix(key, "-----BEGIN PRIVATE KEY-----\n") {
		t.Errorf("TLS_KEY missing leading newline structure: %q", key)
	}
	if !strings.HasSuffix(key, "-----END PRIVATE KEY-----") {
		t.Errorf("TLS_KEY missing trailer: %q", key)
	}
	if strings.Count(key, "\n") != 3 {
		t.Errorf("TLS_KEY newline count = %d, want 3", strings.Count(key, "\n"))
	}
	// Entries before and after the multiline value must still be parsed.
	if v, _ := f.Get("DB_HOST"); v != "db.local" {
		t.Errorf("DB_HOST = %q, want db.local", v)
	}
	if v, _ := f.Get("AFTER"); v != "trailing" {
		t.Errorf("AFTER = %q, want trailing", v)
	}
	if got := f.Keys(); strings.Join(got, ",") != "DB_HOST,TLS_KEY,AFTER" {
		t.Errorf("Keys = %v, want [DB_HOST TLS_KEY AFTER]", got)
	}
}

func TestCRLF(t *testing.T) {
	f := readFixture(t, "crlf.env")
	if f.eol != "\r\n" {
		t.Errorf("detected eol = %q, want CRLF", f.eol)
	}
	for k, want := range map[string]string{"FIRST": "one", "SECOND": "two", "THIRD": "a b"} {
		if v, ok := f.Get(k); !ok || v != want {
			t.Errorf("Get(%q) = %q,%v; want %q", k, v, ok, want)
		}
	}
	// No stray carriage returns should survive into values.
	if v, _ := f.Get("SECOND"); strings.ContainsRune(v, '\r') {
		t.Errorf("SECOND retains a carriage return: %q", v)
	}
}

func TestBOM(t *testing.T) {
	f := readFixture(t, "bom.env")
	if !f.bom {
		t.Error("BOM not detected")
	}
	// The key must be BOM_KEY, with no BOM folded into the name.
	if _, ok := f.Get("BOM_KEY"); !ok {
		t.Errorf("BOM_KEY missing; keys=%v (BOM leaked into first key)", f.Keys())
	}
	for _, k := range f.Keys() {
		if strings.ContainsRune(k, rune(0xFEFF)) {
			t.Errorf("key %q still contains a BOM", k)
		}
	}
}

func TestFormattingPreserved(t *testing.T) {
	input := "# top comment\nexport FOO=bar   # inline\n\nBAZ=\"multi\nline\"\n"
	f := parse(t, input)

	if len(f.nodes) != 4 {
		t.Fatalf("node count = %d, want 4 (comment, entry, blank, entry)", len(f.nodes))
	}
	if f.nodes[0].kind != kindComment || f.nodes[0].raw != "# top comment" {
		t.Errorf("node0 = %+v, want comment '# top comment'", f.nodes[0])
	}
	if f.nodes[1].raw != "export FOO=bar   # inline" {
		t.Errorf("node1 raw = %q, want exact source line", f.nodes[1].raw)
	}
	if f.nodes[2].kind != kindBlank {
		t.Errorf("node2 kind = %v, want blank", f.nodes[2].kind)
	}
	if f.nodes[3].raw != "BAZ=\"multi\nline\"" {
		t.Errorf("node3 raw = %q, want the multiline source", f.nodes[3].raw)
	}
}

func TestGetSetKeys(t *testing.T) {
	f := parse(t, "B=1\nA=2\nC=3")

	if got := strings.Join(f.Keys(), ","); got != "B,A,C" {
		t.Errorf("Keys order = %q, want B,A,C", got)
	}

	// Update existing: value changes, order does not, node is marked dirty.
	f.Set("A", "20")
	if v, _ := f.Get("A"); v != "20" {
		t.Errorf("after Set, A = %q, want 20", v)
	}
	if !f.nodes[f.idx["A"]].dirty {
		t.Error("updated node not marked dirty")
	}
	if got := strings.Join(f.Keys(), ","); got != "B,A,C" {
		t.Errorf("Keys order changed after update: %q", got)
	}

	// New key appends at the end.
	f.Set("D", "4")
	if v, ok := f.Get("D"); !ok || v != "4" {
		t.Errorf("Get(D) = %q,%v; want 4", v, ok)
	}
	if got := strings.Join(f.Keys(), ","); got != "B,A,C,D" {
		t.Errorf("Keys after append = %q, want B,A,C,D", got)
	}

	if _, ok := f.Get("MISSING"); ok {
		t.Error("Get(MISSING) reported present")
	}
}

func TestEmptyInput(t *testing.T) {
	f := parse(t, "")
	if len(f.nodes) != 0 {
		t.Errorf("empty input produced %d nodes, want 0", len(f.nodes))
	}
	if len(f.Keys()) != 0 {
		t.Errorf("empty input produced keys %v", f.Keys())
	}
}

func TestBlankAndCommentOnlyLines(t *testing.T) {
	f := parse(t, "\n   \n# just a comment\n\t# indented comment\n")
	if len(f.Keys()) != 0 {
		t.Errorf("expected no entries, got %v", f.Keys())
	}
	if len(f.nodes) != 4 {
		t.Errorf("node count = %d, want 4", len(f.nodes))
	}
}

func readFixture(t *testing.T, name string) *File {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	f, err := Parse(strings.NewReader(string(data)))
	if err != nil {
		t.Fatalf("parse fixture %s: %v", name, err)
	}
	return f
}
