package keys

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"github.com/BurntSushi/toml"
	"golang.org/x/crypto/ssh"

	"github.com/YehiaGewily/envguardian/internal/atomic"
)

// Recipient is one entry in recipients.toml: a named public key and the
// provenance metadata that makes the file reviewable.
type Recipient struct {
	Name    string   `toml:"name" json:"name"`
	Key     string   `toml:"key,omitempty" json:"key,omitempty"`
	Keys    []string `toml:"keys,omitempty" json:"keys,omitempty"`
	Source  string   `toml:"source" json:"source"`
	AddedAt string   `toml:"added_at" json:"added_at"`
	AddedBy string   `toml:"added_by" json:"added_by"`
}

// RecipientsFile is the parsed recipients.toml. The TOML table is [[recipient]].
type RecipientsFile struct {
	Recipients []Recipient `toml:"recipient"`
}

// LoadRecipients reads and validates recipients.toml.
func LoadRecipients(path string) (*RecipientsFile, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: path is the user-specified recipients file
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("recipients file %s not found: run `envguardian init` first: %w", path, err)
		}
		return nil, fmt.Errorf("read recipients file %s: %w", path, err)
	}
	f, err := ParseRecipients(data)
	if err != nil {
		return nil, fmt.Errorf("parse recipients file %s: %w", path, err)
	}
	return f, nil
}

// ParseRecipients decodes and validates recipients bytes. Hooks use it on
// exact commit blobs so the working tree cannot substitute a different trust
// set during automatic-decryption checks.
func ParseRecipients(data []byte) (*RecipientsFile, error) {
	var f RecipientsFile
	metadata, err := toml.Decode(string(data), &f)
	if err != nil {
		return nil, err
	}
	if undecoded := metadata.Undecoded(); len(undecoded) > 0 {
		return nil, fmt.Errorf("unknown field %q", undecoded[0].String())
	}
	if err := f.Validate(); err != nil {
		return nil, err
	}
	return &f, nil
}

// Save writes the recipients file atomically. It is committed and public, so it
// uses 0644, not the 0600 reserved for plaintext secrets.
func (f *RecipientsFile) Save(path string) error {
	data, err := f.Marshal()
	if err != nil {
		return err
	}
	if err := atomic.WriteFile(path, data, 0o644); err != nil {
		return err
	}
	return nil
}

// Marshal validates and deterministically encodes recipients.toml without
// writing it, so recipient operations can include the bytes in a transaction.
func (f *RecipientsFile) Marshal() ([]byte, error) {
	if err := f.Validate(); err != nil {
		return nil, fmt.Errorf("refusing to encode invalid recipients file: %w", err)
	}
	var b strings.Builder
	if err := toml.NewEncoder(&b).Encode(f); err != nil {
		return nil, fmt.Errorf("encode recipients file: %w", err)
	}
	return []byte(b.String()), nil
}

// Validate enforces the invariants that make the file safe to encrypt against:
// at least one recipient, unique names, unique keys, and well-formed key
// material. Each failure names the offending entry and says what to do.
func (f *RecipientsFile) Validate() error {
	if len(f.Recipients) == 0 {
		return errors.New("no recipients: add one with `envguardian add-recipient`")
	}

	names := make(map[string]int, len(f.Recipients))
	fingerprints := make(map[string]string)

	for i, r := range f.Recipients {
		if strings.TrimSpace(r.Name) == "" {
			return fmt.Errorf("recipient #%d has no name: every recipient needs a unique name", i+1)
		}
		if prev, ok := names[r.Name]; ok {
			return fmt.Errorf("duplicate recipient name %q (entries #%d and #%d): names must be unique", r.Name, prev+1, i+1)
		}
		names[r.Name] = i

		publicKeys := r.PublicKeys()
		if len(publicKeys) == 0 {
			return fmt.Errorf("recipient %q has no key: set legacy key = or keys = [...]", r.Name)
		}
		for keyIndex, key := range publicKeys {
			if _, err := ParseRecipient(key); err != nil {
				return fmt.Errorf("recipient %q key #%d is invalid: %w", r.Name, keyIndex+1, err)
			}

			fp := canonicalKey(key)
			if prev, ok := fingerprints[fp]; ok {
				return fmt.Errorf("recipient key for %q duplicates a key already assigned to %q: every key must be unique within and across people", r.Name, prev)
			}
			fingerprints[fp] = r.Name
		}
	}
	return nil
}

// PublicKeys returns the additive schema's complete key list. Legacy key = is
// accepted on read and flattened together with keys = for migration.
func (r Recipient) PublicKeys() []string {
	out := make([]string, 0, len(r.Keys)+1)
	if strings.TrimSpace(r.Key) != "" {
		out = append(out, r.Key)
	}
	for _, key := range r.Keys {
		if strings.TrimSpace(key) != "" {
			out = append(out, key)
		}
	}
	return out
}

// AgeRecipients parses every entry into an age.Recipient for encryption. It
// assumes the file has been validated; it re-parses and returns the first error
// otherwise.
func (f *RecipientsFile) AgeRecipients() ([]age.Recipient, error) {
	var out []age.Recipient
	for _, r := range f.Recipients {
		for keyIndex, key := range r.PublicKeys() {
			rec, err := ParseRecipient(key)
			if err != nil {
				return nil, fmt.Errorf("recipient %q key #%d: %w", r.Name, keyIndex+1, err)
			}
			out = append(out, rec)
		}
	}
	return out, nil
}

// Names returns the recipient names in file order.
func (f *RecipientsFile) Names() []string {
	out := make([]string, len(f.Recipients))
	for i, r := range f.Recipients {
		out[i] = r.Name
	}
	return out
}

// RecipientNameForPublicKey returns the current recipient that owns key. SSH
// comments are ignored through the same canonicalization used by validation
// and recipient fingerprints.
func (f *RecipientsFile) RecipientNameForPublicKey(key string) (string, bool) {
	want := canonicalKey(key)
	if want == "" {
		return "", false
	}
	for _, recipient := range f.Recipients {
		for _, candidate := range recipient.PublicKeys() {
			if canonicalKey(candidate) == want {
				return recipient.Name, true
			}
		}
	}
	return "", false
}

// RecipientNameForSigningKey returns the recipient whose SSH public key has
// the fingerprint reported by git for a verified SSH commit signature. age
// X25519 recipients cannot sign commits and therefore never match.
func (f *RecipientsFile) RecipientNameForSigningKey(fingerprint string) (string, bool) {
	want := strings.TrimSpace(fingerprint)
	if want == "" {
		return "", false
	}
	for _, recipient := range f.Recipients {
		for _, key := range recipient.PublicKeys() {
			if !strings.HasPrefix(strings.TrimSpace(key), "ssh-") {
				continue
			}
			pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(key))
			if err != nil {
				continue
			}
			if strings.EqualFold(want, ssh.FingerprintSHA256(pub)) || strings.EqualFold(want, ssh.FingerprintLegacyMD5(pub)) {
				return recipient.Name, true
			}
		}
	}
	return "", false
}

// ParseRecipient turns a public key string into an age.Recipient. It accepts
// age X25519 keys (age1...) and SSH public keys (ssh-ed25519, ssh-rsa).
func ParseRecipient(key string) (age.Recipient, error) {
	key = strings.TrimSpace(key)
	switch {
	case strings.HasPrefix(key, "age1"):
		r, err := age.ParseX25519Recipient(key)
		if err != nil {
			return nil, errors.New("not a valid age recipient")
		}
		return r, nil
	case strings.HasPrefix(key, "ssh-"):
		r, err := agessh.ParseRecipient(key)
		if err != nil {
			return nil, errors.New("not a valid SSH recipient (only ssh-ed25519 and ssh-rsa are supported)")
		}
		return r, nil
	default:
		return nil, errors.New("unrecognized key: expected an age1... or ssh-ed25519/ssh-rsa public key")
	}
}

// canonicalKey canonicalizes a key for duplicate detection and for the
// recipient-set fingerprint. SSH keys are reduced to "type base64" so the same
// key with a different trailing comment still collides.
func canonicalKey(key string) string {
	key = strings.TrimSpace(key)
	if strings.HasPrefix(key, "ssh-") {
		fields := strings.Fields(key)
		if len(fields) >= 2 {
			return fields[0] + " " + fields[1]
		}
	}
	return key
}

// fingerprintScheme versions the canonicalization + hashing below, so it can
// change later without a flag day (old locks simply mismatch and re-encrypt).
const fingerprintScheme = "v1"

// Fingerprint returns a version-prefixed SHA-256 over the sorted, canonicalized
// recipient public keys. It is a derivative of PUBLIC data only (recipient
// keys), never of any secret value; see CONTRIBUTING.md. Lock v2 records it as
// a recipient-set signal, not as ciphertext provenance.
func (f *RecipientsFile) Fingerprint() string {
	var canon []string
	for _, r := range f.Recipients {
		for _, key := range r.PublicKeys() {
			canon = append(canon, canonicalKey(key))
		}
	}
	sort.Strings(canon)
	sum := sha256.Sum256([]byte(strings.Join(canon, "\n")))
	return fingerprintScheme + ":" + hex.EncodeToString(sum[:])
}
