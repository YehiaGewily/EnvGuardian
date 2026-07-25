package dotenv

import (
	"fmt"
	"io"
	"strings"
)

// QuoteStyle records how a value was quoted in the source file. It is retained
// so the (future) serializer can re-emit an unchanged value byte-for-byte.
type QuoteStyle int

const (
	// QuoteNone is an unquoted value.
	QuoteNone QuoteStyle = iota
	// QuoteSingle is a single-quoted (fully literal) value.
	QuoteSingle
	// QuoteDouble is a double-quoted (escape- and interpolation-expanded) value.
	QuoteDouble
)

// String renders the quote style for diagnostics.
func (q QuoteStyle) String() string {
	switch q {
	case QuoteSingle:
		return "single"
	case QuoteDouble:
		return "double"
	default:
		return "none"
	}
}

// Entry is a single KEY=VALUE binding. Value is fully decoded: escapes are
// expanded and ${VAR} references are resolved. Comment holds the inline comment
// text (without the leading '#'), if any. Line is the 1-based line where the
// entry begins.
type Entry struct {
	Key     string
	Value   string
	Quote   QuoteStyle
	Comment string
	Line    int
}

// nodeKind distinguishes the three kinds of source line the parser preserves.
type nodeKind int

const (
	kindBlank nodeKind = iota
	kindComment
	kindEntry
)

// node is one preserved unit of the source file: a blank line, a comment line,
// or an entry (which may span several physical lines for a multiline value).
// raw is the original text with internal line breaks normalized to '\n'; it is
// what the serializer re-emits verbatim for untouched entries.
type node struct {
	kind   nodeKind
	raw    string
	export bool
	entry  *Entry
	dirty  bool // set by Set: the serializer must re-render rather than use raw
}

// File is a parsed .env file. It preserves comments, blank lines, key order,
// quote style, export prefixes, and the file's dominant line ending so the
// serializer can round-trip untouched content byte-for-byte.
type File struct {
	nodes   []node
	idx     map[string]int // key -> index into nodes
	eol     string         // dominant line ending: "\n" or "\r\n"
	bom     bool           // input began with a UTF-8 BOM (stripped)
	trailNL bool           // input ended with a newline
}

// ParseError reports a malformed line. It always carries a 1-based line number
// and, where possible, a hint describing how to fix it.
type ParseError struct {
	Line int
	Msg  string
	Hint string
}

func (e *ParseError) Error() string {
	if e.Hint != "" {
		return fmt.Sprintf("line %d: %s (%s)", e.Line, e.Msg, e.Hint)
	}
	return fmt.Sprintf("line %d: %s", e.Line, e.Msg)
}

// Parse reads a .env file and returns its structured, order-preserving form.
// A leading UTF-8 BOM and CRLF line endings are tolerated. Duplicate keys, bare
// keys without '=', undefined ${VAR} references, and unterminated quotes are
// errors.
func Parse(r io.Reader) (*File, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	content := string(data)

	f := &File{idx: make(map[string]int), eol: "\n"}

	bom := string(rune(0xFEFF)) // UTF-8 BOM
	if strings.HasPrefix(content, bom) {
		f.bom = true
		content = strings.TrimPrefix(content, bom)
	}

	// Detect the dominant line ending before normalizing.
	crlf := strings.Count(content, "\r\n")
	lf := strings.Count(content, "\n") - crlf
	if crlf > lf {
		f.eol = "\r\n"
	}
	content = strings.ReplaceAll(content, "\r\n", "\n")
	content = strings.ReplaceAll(content, "\r", "\n")
	f.trailNL = strings.HasSuffix(content, "\n")

	var lines []string
	if content != "" {
		lines = strings.Split(content, "\n")
		// A trailing newline yields a spurious empty final element; drop it.
		if strings.HasSuffix(content, "\n") {
			lines = lines[:len(lines)-1]
		}
	}

	vals := make(map[string]string) // resolved values for interpolation

	i := 0
	for i < len(lines) {
		line := lines[i]
		trimmed := strings.TrimLeft(line, " \t")

		switch {
		case trimmed == "":
			f.nodes = append(f.nodes, node{kind: kindBlank, raw: line})
			i++
		case trimmed[0] == '#':
			f.nodes = append(f.nodes, node{kind: kindComment, raw: line})
			i++
		default:
			ent, export, endIdx, err := parseEntry(lines, i, vals)
			if err != nil {
				return nil, err
			}
			if prev, ok := f.idx[ent.Key]; ok {
				return nil, &ParseError{
					Line: ent.Line,
					Msg:  fmt.Sprintf("duplicate key %q", ent.Key),
					Hint: fmt.Sprintf("first defined on line %d; remove one", f.nodes[prev].entry.Line),
				}
			}
			f.idx[ent.Key] = len(f.nodes)
			f.nodes = append(f.nodes, node{
				kind:   kindEntry,
				raw:    strings.Join(lines[i:endIdx+1], "\n"),
				export: export,
				entry:  ent,
			})
			vals[ent.Key] = ent.Value
			i = endIdx + 1
		}
	}

	return f, nil
}

// parseEntry parses the entry beginning at lines[start]. It returns the entry,
// whether it had an `export` prefix, and the index of the last physical line it
// consumed (values may span lines when quoted).
func parseEntry(lines []string, start int, vals map[string]string) (*Entry, bool, int, error) {
	line := lines[start]
	lineNo := start + 1

	// Leading whitespace.
	j := 0
	for j < len(line) && (line[j] == ' ' || line[j] == '\t') {
		j++
	}
	rest := line[j:]

	// Optional `export ` prefix (requires trailing whitespace so a key literally
	// named "export" or "export_X" is not mistaken for the prefix).
	export := false
	if strings.HasPrefix(rest, "export") {
		after := rest[len("export"):]
		if len(after) > 0 && (after[0] == ' ' || after[0] == '\t') {
			export = true
			k := len("export")
			for k < len(rest) && (rest[k] == ' ' || rest[k] == '\t') {
				k++
			}
			rest = rest[k:]
		}
	}

	if len(rest) == 0 || rest[0] == '=' {
		return nil, false, start, &ParseError{
			Line: lineNo, Msg: "missing variable name before '='", Hint: "use KEY=value",
		}
	}
	if !isKeyStart(rest[0]) {
		return nil, false, start, &ParseError{
			Line: lineNo,
			Msg:  fmt.Sprintf("unexpected character %q at start of key", string(rest[0])),
			Hint: "keys must start with a letter or underscore",
		}
	}

	ke := 0
	for ke < len(rest) && isKeyChar(rest[ke]) {
		ke++
	}
	key := rest[:ke]
	rem := rest[ke:]

	m := 0
	for m < len(rem) && (rem[m] == ' ' || rem[m] == '\t') {
		m++
	}
	if m >= len(rem) || rem[m] != '=' {
		return nil, false, start, &ParseError{
			Line: lineNo,
			Msg:  fmt.Sprintf("missing '=' after key %q", key),
			Hint: "bare keys are not allowed; write " + key + "=value",
		}
	}

	valStartCol := len(line) - len(rem) + m + 1
	value, quote, comment, endIdx, err := scanValue(lines, start, valStartCol, lineNo, vals)
	if err != nil {
		return nil, false, start, err
	}

	return &Entry{Key: key, Value: value, Quote: quote, Comment: comment, Line: lineNo}, export, endIdx, nil
}

// scanValue parses the value beginning at lines[li][col] (col is just past '=').
func scanValue(lines []string, li, col, lineNo int, vals map[string]string) (string, QuoteStyle, string, int, error) {
	line := lines[li]
	valPart := line[col:]

	w := 0
	for w < len(valPart) && (valPart[w] == ' ' || valPart[w] == '\t') {
		w++
	}
	if w < len(valPart) && valPart[w] == '"' {
		return scanDouble(lines, li, col+w, lineNo, vals)
	}
	if w < len(valPart) && valPart[w] == '\'' {
		return scanSingle(lines, li, col+w, lineNo)
	}

	// Unquoted. A '#' starts an inline comment only when preceded by whitespace,
	// so values like sec#ret and http://h/#frag survive intact.
	ci := -1
	for x := 0; x < len(valPart); x++ {
		if valPart[x] == '#' && x > 0 && (valPart[x-1] == ' ' || valPart[x-1] == '\t') {
			ci = x
			break
		}
	}
	raw := valPart
	comment := ""
	if ci >= 0 {
		raw = valPart[:ci]
		comment = strings.TrimSpace(valPart[ci+1:])
	}
	value, err := interpolate(strings.Trim(raw, " \t"), lineNo, vals)
	if err != nil {
		return "", QuoteNone, "", li, err
	}
	return value, QuoteNone, comment, li, nil
}

// scanDouble scans a double-quoted value (escapes expanded, ${VAR} interpolated,
// may span lines). col points at the opening quote.
func scanDouble(lines []string, li, col, lineNo int, vals map[string]string) (string, QuoteStyle, string, int, error) {
	var inner strings.Builder
	cl, cc := li, col+1
	for {
		if cc >= len(lines[cl]) {
			inner.WriteByte('\n')
			cl++
			cc = 0
			if cl >= len(lines) {
				return "", QuoteDouble, "", li, &ParseError{
					Line: lineNo, Msg: "unterminated double-quoted value",
					Hint: `add a closing " or check for a stray quote`,
				}
			}
			continue
		}
		ch := lines[cl][cc]
		switch ch {
		case '\\':
			if cc+1 < len(lines[cl]) {
				inner.WriteByte('\\')
				inner.WriteByte(lines[cl][cc+1])
				cc += 2
			} else {
				inner.WriteByte('\\')
				cc++
			}
		case '"':
			cc++
			expanded, err := interpolate(inner.String(), lineNo, vals)
			if err != nil {
				return "", QuoteDouble, "", cl, err
			}
			comment, err := trailing(lines[cl], cc, lineNo)
			if err != nil {
				return "", QuoteDouble, "", cl, err
			}
			return decodeEscapes(expanded), QuoteDouble, comment, cl, nil
		default:
			inner.WriteByte(ch)
			cc++
		}
	}
}

// scanSingle scans a single-quoted value (fully literal, may span lines). col
// points at the opening quote.
func scanSingle(lines []string, li, col, lineNo int) (string, QuoteStyle, string, int, error) {
	var inner strings.Builder
	cl, cc := li, col+1
	for {
		if cc >= len(lines[cl]) {
			inner.WriteByte('\n')
			cl++
			cc = 0
			if cl >= len(lines) {
				return "", QuoteSingle, "", li, &ParseError{
					Line: lineNo, Msg: "unterminated single-quoted value",
					Hint: "add a closing '",
				}
			}
			continue
		}
		if lines[cl][cc] == '\'' {
			cc++
			comment, err := trailing(lines[cl], cc, lineNo)
			if err != nil {
				return "", QuoteSingle, "", cl, err
			}
			return inner.String(), QuoteSingle, comment, cl, nil
		}
		inner.WriteByte(lines[cl][cc])
		cc++
	}
}

// trailing validates the text after a closing quote: only whitespace and an
// optional '#' comment are allowed.
func trailing(line string, pos, lineNo int) (string, error) {
	t := strings.TrimLeft(line[pos:], " \t")
	switch {
	case t == "":
		return "", nil
	case t[0] == '#':
		return strings.TrimSpace(t[1:]), nil
	default:
		return "", &ParseError{
			Line: lineNo,
			Msg:  fmt.Sprintf("unexpected text after closing quote: %q", t),
			Hint: "wrap the whole value in quotes, or put a space before the # comment",
		}
	}
}

// interpolate resolves ${VAR} and $VAR references against vals (keys defined
// earlier in the file). `\$` yields a literal '$'; `\\` is preserved for the
// escape decoder. An undefined reference is an error.
func interpolate(s string, lineNo int, vals map[string]string) (string, error) {
	if !strings.ContainsAny(s, "$\\") {
		return s, nil
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		c := s[i]
		if c == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case '$':
				b.WriteByte('$')
				i += 2
			case '\\':
				b.WriteString(`\\`)
				i += 2
			default:
				b.WriteByte('\\')
				i++
			}
			continue
		}
		if c == '$' {
			name, adv, isRef, err := parseRef(s, i, lineNo)
			if err != nil {
				return "", err
			}
			if !isRef {
				b.WriteByte('$')
				i++
				continue
			}
			v, ok := vals[name]
			if !ok {
				return "", &ParseError{
					Line: lineNo,
					Msg:  fmt.Sprintf("undefined variable %q", name),
					Hint: `define it earlier in the file, or escape it as \$`,
				}
			}
			b.WriteString(v)
			i += adv
			continue
		}
		b.WriteByte(c)
		i++
	}
	return b.String(), nil
}

// parseRef parses a variable reference at s[i] (which is '$'). It returns the
// name, how many bytes the reference spans, and whether it was a reference at
// all (a lone '$' is a literal dollar sign).
func parseRef(s string, i, lineNo int) (name string, adv int, isRef bool, err error) {
	if i+1 >= len(s) {
		return "", 1, false, nil
	}
	if s[i+1] == '{' {
		end := strings.IndexByte(s[i+2:], '}')
		if end < 0 {
			return "", 0, false, &ParseError{
				Line: lineNo, Msg: "unterminated variable reference '${'", Hint: "close it with '}'",
			}
		}
		name = s[i+2 : i+2+end]
		if !validName(name) {
			return "", 0, false, &ParseError{
				Line: lineNo,
				Msg:  fmt.Sprintf("invalid variable name %q in ${...}", name),
				Hint: "use ${NAME} with letters, digits, or underscore",
			}
		}
		return name, end + 3, true, nil
	}
	if isKeyStart(s[i+1]) {
		k := i + 1
		for k < len(s) && isNameChar(s[k]) {
			k++
		}
		return s[i+1 : k], k - i, true, nil
	}
	return "", 1, false, nil
}

// decodeEscapes expands the double-quote escape set. `\$` is not handled here;
// interpolate has already converted it to a literal '$'.
func decodeEscapes(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case 'n':
				b.WriteByte('\n')
				i++
			case 'r':
				b.WriteByte('\r')
				i++
			case 't':
				b.WriteByte('\t')
				i++
			case '\\':
				b.WriteByte('\\')
				i++
			case '"':
				b.WriteByte('"')
				i++
			case '$':
				b.WriteByte('$')
				i++
			default:
				b.WriteByte('\\')
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isKeyStart(b byte) bool {
	return b == '_' || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

func isKeyChar(b byte) bool {
	return isKeyStart(b) || (b >= '0' && b <= '9') || b == '.' || b == '-'
}

func isNameChar(b byte) bool {
	return b == '_' || (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

func validName(s string) bool {
	if s == "" || !isKeyStart(s[0]) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isNameChar(s[i]) {
			return false
		}
	}
	return true
}

// Get returns the decoded value for key and whether it is present.
func (f *File) Get(key string) (string, bool) {
	if i, ok := f.idx[key]; ok {
		return f.nodes[i].entry.Value, true
	}
	return "", false
}

// Set updates key to value, or appends a new entry if key is absent. The value
// is stored literally: Set does not re-run interpolation. Changed entries are
// marked so the serializer re-renders them rather than reusing the raw source.
func (f *File) Set(key, value string) {
	if i, ok := f.idx[key]; ok {
		f.nodes[i].entry.Value = value
		f.nodes[i].dirty = true
		return
	}
	f.idx[key] = len(f.nodes)
	f.nodes = append(f.nodes, node{
		kind:  kindEntry,
		entry: &Entry{Key: key, Value: value, Quote: QuoteNone},
		dirty: true,
	})
}

// Keys returns the entry keys in the order they appear in the file.
func (f *File) Keys() []string {
	keys := make([]string, 0, len(f.idx))
	for _, n := range f.nodes {
		if n.kind == kindEntry {
			keys = append(keys, n.entry.Key)
		}
	}
	return keys
}
