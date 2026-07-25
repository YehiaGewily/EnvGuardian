// Package config reads and writes .envguardian/config.toml, which maps each
// plaintext file to its committed ciphertext, and resolves the conventional
// paths of the .envguardian directory.
package config

import (
	"fmt"
	"os"
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
	}
}

// FilePair maps a plaintext file to its ciphertext file.
type FilePair struct {
	Plaintext  string `toml:"plaintext"`
	Ciphertext string `toml:"ciphertext"`
}

// Config is the parsed config.toml.
type Config struct {
	Version int        `toml:"version"`
	Files   []FilePair `toml:"file"`
}

// Load reads and validates config.toml.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: user-configured config path
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("config %s not found: run `envguardian init` first", path)
		}
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var c Config
	if err := toml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("config %s is invalid: %w", path, err)
	}
	return &c, nil
}

func (c *Config) validate() error {
	if len(c.Files) == 0 {
		return fmt.Errorf("no [[file]] entries: add a plaintext/ciphertext pair")
	}
	for i, f := range c.Files {
		if strings.TrimSpace(f.Plaintext) == "" || strings.TrimSpace(f.Ciphertext) == "" {
			return fmt.Errorf("file #%d must set both plaintext and ciphertext", i+1)
		}
	}
	return nil
}

// Save writes config.toml atomically.
func (c *Config) Save(path string) error {
	var b strings.Builder
	if err := toml.NewEncoder(&b).Encode(c); err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	return atomic.WriteFile(path, []byte(b.String()), 0o644)
}
