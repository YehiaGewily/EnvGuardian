package gitint

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
)

// NotIgnoredError reports plaintext files that git is not ignoring, so encrypt
// can refuse before a secret is committed.
type NotIgnoredError struct {
	Paths []string
}

func (e *NotIgnoredError) Error() string {
	return fmt.Sprintf(
		"plaintext file(s) not ignored by git: %s\n"+
			"  committing plaintext secrets defeats EnvGuardian and leaks them into git history forever.\n"+
			"  fix: add them to .gitignore, or re-run with --fix to append them automatically",
		strings.Join(e.Paths, ", "))
}

// IsIgnored reports whether path (relative to root) is ignored by git. It shells
// out to `git check-ignore`; if git is unavailable or root is not a repo, it
// falls back to parsing .gitignore.
func IsIgnored(root, relPath string) (bool, error) {
	if ignored, usable := gitCheckIgnore(root, relPath); usable {
		return ignored, nil
	}
	return ignoredByGitignoreFile(root, relPath)
}

// gitCheckIgnore runs `git check-ignore -q`. usable is false when git can't
// answer (binary missing, not a repo), signalling the caller to fall back.
func gitCheckIgnore(root, relPath string) (ignored, usable bool) {
	// #nosec G204 -- fixed binary; relPath is a literal argument after "--", no shell.
	cmd := exec.Command("git", "check-ignore", "-q", "--", relPath)
	cmd.Dir = root
	err := cmd.Run()
	if err == nil {
		return true, true // exit 0: ignored
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if exitErr.ExitCode() == 1 {
			return false, true // exit 1: definitively not ignored
		}
		return false, false // 128 (not a repo, etc.): fall back
	}
	return false, false // git not found / failed to start: fall back
}

// ignoredByGitignoreFile is a best-effort fallback matcher over the root
// .gitignore. It handles the common cases (exact name, basename, simple globs,
// and negation); it does not implement git's full pattern semantics.
func ignoredByGitignoreFile(root, relPath string) (bool, error) {
	data, err := os.ReadFile(filepath.Join(root, ".gitignore")) //nolint:gosec // G304: repo-root .gitignore
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("read .gitignore: %w", err)
	}

	target := filepath.ToSlash(relPath)
	base := path.Base(target)
	ignored := false
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		neg := strings.HasPrefix(line, "!")
		pat := strings.TrimPrefix(line, "!")
		pat = strings.TrimPrefix(pat, "/")
		pat = strings.TrimSuffix(pat, "/")
		if matchesPattern(pat, target, base) {
			ignored = !neg
		}
	}
	return ignored, nil
}

func matchesPattern(pat, target, base string) bool {
	if pat == target || pat == base {
		return true
	}
	if ok, _ := path.Match(pat, base); ok {
		return true
	}
	if ok, _ := path.Match(pat, target); ok {
		return true
	}
	return false
}

// EnsureIgnored verifies every path is ignored. When fix is true it appends any
// missing entries to .gitignore and re-verifies. It returns a *NotIgnoredError
// naming anything still unignored.
func EnsureIgnored(root string, relPaths []string, fix bool) error {
	missing, err := unignored(root, relPaths)
	if err != nil {
		return err
	}
	if len(missing) == 0 {
		return nil
	}
	if !fix {
		return &NotIgnoredError{Paths: missing}
	}
	for _, p := range missing {
		if _, err := AppendIgnore(root, p); err != nil {
			return err
		}
	}
	still, err := unignored(root, missing)
	if err != nil {
		return err
	}
	if len(still) > 0 {
		return &NotIgnoredError{Paths: still}
	}
	return nil
}

func unignored(root string, relPaths []string) ([]string, error) {
	var missing []string
	for _, p := range relPaths {
		ig, err := IsIgnored(root, p)
		if err != nil {
			return nil, err
		}
		if !ig {
			missing = append(missing, p)
		}
	}
	return missing, nil
}

// AppendIgnore ensures entry is a line in root/.gitignore, creating the file if
// needed. It returns whether it added the line.
func AppendIgnore(root, entry string) (bool, error) {
	return AppendLine(filepath.Join(root, ".gitignore"), entry)
}

// AppendLine ensures entry is present as its own line in the file at path,
// creating the file if needed. It returns whether it added the line.
func AppendLine(path, entry string) (bool, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: repo-root dotfile (.gitignore/.gitattributes)
	if err != nil && !os.IsNotExist(err) {
		return false, fmt.Errorf("read %s: %w", path, err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == entry {
			return false, nil
		}
	}

	var b strings.Builder
	b.Write(data)
	if len(data) > 0 && !strings.HasSuffix(string(data), "\n") {
		b.WriteByte('\n')
	}
	fmt.Fprintf(&b, "%s\n", entry)
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil { //nolint:gosec // dotfile is not a secret
		return false, fmt.Errorf("write %s: %w", path, err)
	}
	return true, nil
}
