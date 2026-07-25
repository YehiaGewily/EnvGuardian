package dotenv

import (
	"io"
	"strings"
)

// WriteTo serializes the file. For an unmodified file the output is
// byte-identical to the parsed input: comments, blank lines, key order, quote
// style, spacing, the leading BOM, the dominant line ending, and the presence
// or absence of a trailing newline are all preserved.
//
// Entries changed via Set and keys added via Set are the only ones re-rendered;
// they are emitted with the minimal safe quoting (see renderValue) and appended
// in Set order after the original content.
func (f *File) WriteTo(w io.Writer) (int64, error) {
	var b strings.Builder

	if f.bom {
		b.WriteString(string(rune(0xFEFF)))
	}

	for i, n := range f.nodes {
		if i > 0 {
			b.WriteString(f.eol)
		}
		if n.kind == kindEntry && (n.dirty || n.raw == "") {
			b.WriteString(renderEntry(n))
		} else {
			// raw stores internal line breaks as '\n'; restore the file's EOL.
			b.WriteString(strings.ReplaceAll(n.raw, "\n", f.eol))
		}
	}

	if len(f.nodes) > 0 && f.trailNL {
		b.WriteString(f.eol)
	}

	n, err := io.WriteString(w, b.String())
	return int64(n), err
}

// renderEntry renders a changed or newly-added entry as a single line.
func renderEntry(n node) string {
	var b strings.Builder
	if n.export {
		b.WriteString("export ")
	}
	b.WriteString(n.entry.Key)
	b.WriteByte('=')
	b.WriteString(renderValue(n.entry.Value))
	if n.entry.Comment != "" {
		b.WriteString(" # ")
		b.WriteString(n.entry.Comment)
	}
	return b.String()
}

// renderValue picks the minimal quoting that round-trips value exactly:
//   - unquoted when the value contains nothing the parser would reinterpret;
//   - single-quoted (fully literal) when it has specials but no single quote;
//   - double-quoted with escaping otherwise.
func renderValue(value string) string {
	if value == "" {
		return ""
	}
	if isSafeUnquoted(value) {
		return value
	}
	// Single quotes are fully literal — ideal when there's no single quote to
	// escape and no newline (which we prefer to keep on one line as \n).
	if !strings.ContainsAny(value, "'\n\r") {
		return "'" + value + "'"
	}
	return `"` + escapeForDouble(value) + `"`
}

// isSafeUnquoted reports whether value can be written without quotes and parse
// back unchanged. Conservative: any whitespace, comment, quote, backslash, or
// dollar sign forces quoting.
func isSafeUnquoted(value string) bool {
	for i := 0; i < len(value); i++ {
		switch value[i] {
		case ' ', '\t', '\n', '\r', '#', '"', '\'', '\\', '$':
			return false
		}
	}
	return true
}

// escapeForDouble escapes a value for a double-quoted context, including `\$`
// so the parser does not attempt interpolation on the way back in.
func escapeForDouble(value string) string {
	var b strings.Builder
	for i := 0; i < len(value); i++ {
		switch value[i] {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '$':
			b.WriteString(`\$`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteByte(value[i])
		}
	}
	return b.String()
}
