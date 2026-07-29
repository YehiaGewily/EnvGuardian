// Package rotation owns the public, committed ledger of dotenv key names that
// must be rotated after a recipient is revoked. It never stores values or any
// derivative of a plaintext value.
package rotation

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/YehiaGewily/envguardian/internal/atomic"
)

const (
	// FileName is the repository metadata file below .envguardian.
	FileName = "rotation.toml"
	// Version is the current rotation-ledger schema version.
	Version = 1
	header  = "# public key names pending rotation; never put secret values here\n"
)

// Pending records one dotenv key name a revoked recipient could read.
type Pending struct {
	Key string `toml:"key" json:"key"`
}

// Ledger is the strict rotation.toml schema.
type Ledger struct {
	Version int       `toml:"version" json:"version"`
	Pending []Pending `toml:"pending" json:"pending"`
}

// New returns an empty current-version ledger.
func New() *Ledger { return &Ledger{Version: Version} }

// Load reads a ledger. A missing ledger means no revocation has created
// pending work yet; every other read or parse failure is returned.
func Load(path string) (*Ledger, error) {
	data, err := os.ReadFile(path) //nolint:gosec // validated repository metadata path
	if errors.Is(err, os.ErrNotExist) {
		return New(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("cannot read rotation ledger %s: %w", path, err)
	}
	ledger, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("rotation ledger %s is invalid: %w", path, err)
	}
	return ledger, nil
}

// Parse decodes and strictly validates committed ledger bytes.
func Parse(data []byte) (*Ledger, error) {
	var ledger Ledger
	metadata, err := toml.Decode(string(data), &ledger)
	if err != nil {
		return nil, errors.New("malformed TOML")
	}
	if undecoded := metadata.Undecoded(); len(undecoded) > 0 {
		return nil, fmt.Errorf("unknown field %q", undecoded[0].String())
	}
	if ledger.Version != Version {
		return nil, fmt.Errorf("unsupported version %d (want %d)", ledger.Version, Version)
	}
	if err := ledger.validate(); err != nil {
		return nil, err
	}
	ledger.normalize()
	return &ledger, nil
}

func (l *Ledger) validate() error {
	seen := make(map[string]struct{}, len(l.Pending))
	for i, pending := range l.Pending {
		key := strings.TrimSpace(pending.Key)
		if key == "" {
			return fmt.Errorf("pending entry #%d has an empty key name", i+1)
		}
		if strings.ContainsAny(key, "\r\n") {
			return fmt.Errorf("pending entry #%d has an invalid key name", i+1)
		}
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("duplicate pending key %q", key)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func (l *Ledger) normalize() {
	for i := range l.Pending {
		l.Pending[i].Key = strings.TrimSpace(l.Pending[i].Key)
	}
	sort.Slice(l.Pending, func(i, j int) bool { return l.Pending[i].Key < l.Pending[j].Key })
}

// AddKeys adds unique key names and keeps output deterministic.
func (l *Ledger) AddKeys(keys []string) error {
	if l.Version == 0 {
		l.Version = Version
	}
	seen := make(map[string]struct{}, len(l.Pending)+len(keys))
	for _, pending := range l.Pending {
		seen[pending.Key] = struct{}{}
	}
	for _, raw := range keys {
		key := strings.TrimSpace(raw)
		if key == "" || strings.ContainsAny(key, "\r\n") {
			return errors.New("cannot add an empty or invalid rotation key name")
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		l.Pending = append(l.Pending, Pending{Key: key})
	}
	if err := l.validate(); err != nil {
		return err
	}
	l.normalize()
	return nil
}

// Done removes one exact key name. It returns false when the key was not
// pending, allowing the CLI to fail instead of silently claiming success.
func (l *Ledger) Done(key string) bool {
	key = strings.TrimSpace(key)
	for i, pending := range l.Pending {
		if pending.Key != key {
			continue
		}
		l.Pending = append(l.Pending[:i], l.Pending[i+1:]...)
		return true
	}
	return false
}

// Keys returns a copy of pending key names in deterministic order.
func (l *Ledger) Keys() []string {
	out := make([]string, len(l.Pending))
	for i, pending := range l.Pending {
		out[i] = pending.Key
	}
	return out
}

// Marshal validates and encodes the public ledger without writing it.
func (l *Ledger) Marshal() ([]byte, error) {
	if l.Version != Version {
		return nil, fmt.Errorf("unsupported version %d (want %d)", l.Version, Version)
	}
	if err := l.validate(); err != nil {
		return nil, err
	}
	l.normalize()
	var out strings.Builder
	out.WriteString(header)
	if err := toml.NewEncoder(&out).Encode(l); err != nil {
		return nil, fmt.Errorf("encode rotation ledger: %w", err)
	}
	return []byte(out.String()), nil
}

// Save writes the public ledger atomically.
func (l *Ledger) Save(path string) error {
	data, err := l.Marshal()
	if err != nil {
		return err
	}
	return atomic.WriteFile(path, data, 0o644)
}
