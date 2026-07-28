// Package config reads and writes .envguardian/config.toml, which maps each
// plaintext file to its committed ciphertext, and resolves the conventional
// paths of the .envguardian directory.
package config

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/YehiaGewily/envguardian/internal/atomic"
)

const (
	// Dir is the per-repo directory holding all EnvGuardian state.
	Dir = ".envguardian"
	// ConfigFile maps plaintext files to ciphertext files.
	ConfigFile = "config.toml"
	// RecipientsFile lists who can decrypt.
	RecipientsFile = "recipients.toml"
	// LockFile records the recipient-set fingerprint.
	LockFile = "lock.toml"
	// AutoDecryptStateFile records the last commit explicitly accepted or
	// successfully processed by the automatic-decryption hook. It is local and
	// must remain gitignored.
	AutoDecryptStateFile = "auto-decrypt-state.toml"
	// AutoDecryptStateRelative is the repository-relative state-file path.
	AutoDecryptStateRelative = Dir + "/" + AutoDecryptStateFile

	// Version is the current config schema version.
	Version = 1
)

// Paths bundles the conventional file locations for a repo root.
type Paths struct {
	Root       string
	Dir        string
	Config     string
	Recipients string
	Lock       string
	State      string
}

// PathsFor returns the conventional paths for a repo root (".", usually).
func PathsFor(root string) Paths {
	dir := filepath.Join(root, Dir)
	return Paths{
		Root:       root,
		Dir:        dir,
		Config:     filepath.Join(dir, ConfigFile),
		Recipients: filepath.Join(dir, RecipientsFile),
		Lock:       filepath.Join(dir, LockFile),
		State:      filepath.Join(dir, AutoDecryptStateFile),
	}
}

// FilePair maps a plaintext file to its ciphertext file.
type FilePair struct {
	Plaintext      string `toml:"plaintext"`
	Ciphertext     string `toml:"ciphertext"`
	PlaintextPath  string `toml:"-"`
	CiphertextPath string `toml:"-"`
}

// Config is the parsed config.toml.
type Config struct {
	Version int        `toml:"version"`
	Files   []FilePair `toml:"file"`
}

// Load reads config.toml and resolves every managed path against root. A
// successfully loaded Config is safe for commands to consume directly; path
// validation is not repeated command-by-command.
func Load(root, configPath string) (*Config, error) {
	data, err := os.ReadFile(configPath) //nolint:gosec // G304: user-selected config path
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("config %s not found: run `envguardian init` first: %w", configPath, err)
		}
		return nil, fmt.Errorf("read config %s: %w", configPath, err)
	}
	c, err := Parse(root, data)
	if err != nil {
		return nil, fmt.Errorf("config %s is invalid: %w", configPath, err)
	}
	return c, nil
}

// Parse decodes config bytes and resolves all managed paths against root. It is
// used by hooks to validate a config read from an exact commit snapshot.
func Parse(root string, data []byte) (*Config, error) {
	var c Config
	metadata, err := toml.Decode(string(data), &c)
	if err != nil {
		return nil, fmt.Errorf("parse TOML: %w", err)
	}
	if undecoded := metadata.Undecoded(); len(undecoded) > 0 {
		return nil, fmt.Errorf("unknown config field %q", undecoded[0].String())
	}
	if err := c.ValidateAndResolve(root); err != nil {
		return nil, err
	}
	return &c, nil
}

// ValidateAndResolve validates all mappings and populates the absolute resolved
// paths used by commands. It also detects aliases caused by cleaning, symlinks,
// and hard links.
func (c *Config) ValidateAndResolve(root string) error {
	if c.Version != Version {
		return fmt.Errorf("unsupported config version %d (want %d)", c.Version, Version)
	}
	if len(c.Files) == 0 {
		return fmt.Errorf("no [[file]] entries: add a plaintext/ciphertext pair")
	}
	for i := range c.Files {
		f := &c.Files[i]
		if strings.TrimSpace(f.Plaintext) == "" || strings.TrimSpace(f.Ciphertext) == "" {
			return fmt.Errorf("file #%d must set both plaintext and ciphertext", i+1)
		}
		plain, err := ResolveManagedPath(root, f.Plaintext)
		if err != nil {
			return fmt.Errorf("file #%d plaintext %q: %w", i+1, f.Plaintext, err)
		}
		cipher, err := ResolveManagedPath(root, f.Ciphertext)
		if err != nil {
			return fmt.Errorf("file #%d ciphertext %q: %w", i+1, f.Ciphertext, err)
		}
		f.PlaintextPath = plain
		f.CiphertextPath = cipher
	}

	for i := range c.Files {
		for j := 0; j < i; j++ {
			if sameManagedFile(c.Files[i].PlaintextPath, c.Files[j].PlaintextPath) {
				return fmt.Errorf("duplicate plaintext mappings %q and %q resolve to the same file", c.Files[j].Plaintext, c.Files[i].Plaintext)
			}
			if sameManagedFile(c.Files[i].CiphertextPath, c.Files[j].CiphertextPath) {
				return fmt.Errorf("duplicate ciphertext mappings %q and %q resolve to the same file", c.Files[j].Ciphertext, c.Files[i].Ciphertext)
			}
		}
	}
	for i := range c.Files {
		for j := range c.Files {
			if sameManagedFile(c.Files[i].PlaintextPath, c.Files[j].CiphertextPath) {
				return fmt.Errorf("plaintext %q and ciphertext %q resolve to the same file", c.Files[i].Plaintext, c.Files[j].Ciphertext)
			}
		}
	}
	if len(c.Files) != 1 {
		return fmt.Errorf("v0.1.1 supports exactly one [[file]] mapping; use a second --config file for another pair until transactional multi-file support returns in v0.2.0")
	}
	return nil
}

// ResolveManagedPath resolves a repository-controlled path beneath root. It
// rejects platform-independent absolute forms, traversal, .git destinations,
// and symlink escapes through any existing parent.
func ResolveManagedPath(root, configured string) (string, error) {
	if strings.TrimSpace(configured) == "" {
		return "", errors.New("path is empty")
	}

	// Treat both slash styles as separators on every host so a config rejected
	// on Linux cannot become dangerous when the same repository is used on
	// Windows. Drive-relative paths (C:foo) are rejected along with C:\foo.
	portable := strings.ReplaceAll(configured, `\`, "/")
	if filepath.IsAbs(configured) || path.IsAbs(portable) || hasWindowsVolume(portable) || strings.HasPrefix(portable, "//") {
		return "", errors.New("absolute paths are not allowed")
	}
	if strings.Contains(portable, ":") {
		return "", errors.New("colon is not allowed in managed paths because it can address Windows alternate data streams")
	}
	local := filepath.FromSlash(portable)

	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve repository root: %w", err)
	}
	rootResolved, err := filepath.EvalSymlinks(rootAbs)
	if err != nil {
		return "", fmt.Errorf("resolve repository root symlinks: %w", err)
	}

	joined := filepath.Clean(filepath.Join(rootResolved, local))
	if rel, ok := containedRelative(rootResolved, joined); !ok {
		return "", errors.New("path escapes the repository")
	} else if rel == "." {
		return "", errors.New("path resolves to the repository root")
	} else if insideGit(rel) {
		return "", errors.New("paths inside .git are forbidden")
	}

	resolved, err := evalExistingParents(joined)
	if err != nil {
		return "", fmt.Errorf("resolve existing parent symlinks: %w", err)
	}
	rel, ok := containedRelative(rootResolved, resolved)
	if !ok {
		return "", errors.New("path escapes the repository through a symlink")
	}
	if rel == "." {
		return "", errors.New("path resolves to the repository root")
	}
	if insideGit(rel) {
		return "", errors.New("paths inside .git are forbidden")
	}
	return resolved, nil
}

func hasWindowsVolume(portable string) bool {
	return len(portable) >= 2 && ((portable[0] >= 'A' && portable[0] <= 'Z') ||
		(portable[0] >= 'a' && portable[0] <= 'z')) && portable[1] == ':'
}

func containedRelative(root, target string) (string, bool) {
	rel, err := filepath.Rel(root, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", false
	}
	return rel, true
}

func insideGit(rel string) bool {
	if rel == "." {
		return false
	}
	first := strings.SplitN(filepath.ToSlash(rel), "/", 2)[0]
	first = strings.TrimRight(first, " .") // Win32 aliases .git. and .git<space> to .git
	return strings.EqualFold(first, ".git")
}

// evalExistingParents evaluates symlinks at the deepest existing ancestor and
// then restores any not-yet-created suffix.
func evalExistingParents(target string) (string, error) {
	current := target
	var suffix []string
	for {
		_, err := os.Lstat(current)
		switch {
		case err == nil:
			resolved, evalErr := filepath.EvalSymlinks(current)
			if evalErr != nil {
				return "", evalErr
			}
			for i := len(suffix) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, suffix[i])
			}
			return filepath.Clean(resolved), nil
		case !os.IsNotExist(err):
			return "", err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", fmt.Errorf("no existing ancestor for %s", target)
		}
		suffix = append(suffix, filepath.Base(current))
		current = parent
	}
}

func sameManagedFile(a, b string) bool {
	if strings.EqualFold(filepath.Clean(a), filepath.Clean(b)) {
		return true
	}
	aInfo, aErr := os.Stat(a)
	bInfo, bErr := os.Stat(b)
	return aErr == nil && bErr == nil && os.SameFile(aInfo, bInfo)
}

// Save writes config.toml atomically.
func (c *Config) Save(path string) error {
	var b strings.Builder
	if err := toml.NewEncoder(&b).Encode(c); err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	return atomic.WriteFile(path, []byte(b.String()), 0o644)
}
