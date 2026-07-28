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
	Name    string `toml:"name"`
	Key     string `toml:"key"`
	Source  string `toml:"source"`
	AddedAt string `toml:"added_at"`
	AddedBy string `toml:"added_by"`
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
			return nil, fmt.Errorf("recipients file %s not found: run `envguardian init` first", path)
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
	if err := toml.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	if err := f.Validate(); err != nil {
		return nil, err
	}
	return &f, nil
}

// Save writes the recipients file atomically. It is committed and public, so it
// uses 0644, not the 0600 reserved for plaintext secrets.
func (f *RecipientsFile) Save(path string) error {
	if err := f.Validate(); err != nil {
		return fmt.Errorf("refusing to save invalid recipients file: %w", err)
	}
	var b strings.Builder
	if err := toml.NewEncoder(&b).Encode(f); err != nil {
		return fmt.Errorf("encode recipients file: %w", err)
	}
	if err := atomic.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		return err
	}
	return nil
}

// Validate enforces the invariants that make the file safe to encrypt against:
// at least one recipient, unique names, unique keys, and well-formed key
// material. Each failure names the offending entry and says what to do.
func (f *RecipientsFile) Validate() error {
	if len(f.Recipients) == 0 {
		return errors.New("no recipients: add one with `envguardian add-recipient`")
	}

	names := make(map[string]int, len(f.Recipients))
	fingerprints := make(map[string]string, len(f.Recipients))

	for i, r := range f.Recipients {
		if strings.TrimSpace(r.Name) == "" {
			return fmt.Errorf("recipient #%d has no name: every recipient needs a unique name", i+1)
		}
		if prev, ok := names[r.Name]; ok {
			return fmt.Errorf("duplicate recipient name %q (entries #%d and #%d): names must be unique", r.Name, prev+1, i+1)
		}
		names[r.Name] = i

		if strings.TrimSpace(r.Key) == "" {
			return fmt.Errorf("recipient %q has no key: provide an age1... or ssh-ed25519/ssh-rsa public key", r.Name)
		}
		if _, err := ParseRecipient(r.Key); err != nil {
			return fmt.Errorf("recipient %q has an invalid key: %w", r.Name, err)
		}

		fp := canonicalKey(r.Key)
		if prev, ok := fingerprints[fp]; ok {
			return fmt.Errorf("recipients %q and %q share the same key: remove the duplicate", prev, r.Name)
		}
		fingerprints[fp] = r.Name
	}
	return nil
}

// AgeRecipients parses every entry into an age.Recipient for encryption. It
// assumes the file has been validated; it re-parses and returns the first error
// otherwise.
func (f *RecipientsFile) AgeRecipients() ([]age.Recipient, error) {
	out := make([]age.Recipient, 0, len(f.Recipients))
	for _, r := range f.Recipients {
		rec, err := ParseRecipient(r.Key)
		if err != nil {
			return nil, fmt.Errorf("recipient %q: %w", r.Name, err)
		}
		out = append(out, rec)
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

// RecipientNameForSigningKey returns the recipient whose SSH public key has
// the fingerprint reported by git for a verified SSH commit signature. age
// X25519 recipients cannot sign commits and therefore never match.
func (f *RecipientsFile) RecipientNameForSigningKey(fingerprint string) (string, bool) {
	want := strings.TrimSpace(fingerprint)
	if want == "" {
		return "", false
	}
	for _, recipient := range f.Recipients {
		if !strings.HasPrefix(strings.TrimSpace(recipient.Key), "ssh-") {
			continue
		}
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(recipient.Key))
		if err != nil {
			continue
		}
		if strings.EqualFold(want, ssh.FingerprintSHA256(pub)) || strings.EqualFold(want, ssh.FingerprintLegacyMD5(pub)) {
			return recipient.Name, true
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
			return nil, fmt.Errorf("not a valid age recipient: %w", err)
		}
		return r, nil
	case strings.HasPrefix(key, "ssh-"):
		r, err := agessh.ParseRecipient(key)
		if err != nil {
			return nil, fmt.Errorf("not a valid SSH recipient (only ssh-ed25519 and ssh-rsa are supported): %w", err)
		}
		return r, nil
	default:
		preview := key
		if len(preview) > 16 {
			preview = preview[:16] + "…"
		}
		return nil, fmt.Errorf("unrecognized key %q: expected an age1... or ssh-ed25519/ssh-rsa public key", preview)
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
// keys), never of any secret value; see CONTRIBUTING.md. The prototype
// lock.toml records it as a recipient-set signal, not as ciphertext provenance.
func (f *RecipientsFile) Fingerprint() string {
	canon := make([]string, len(f.Recipients))
	for i, r := range f.Recipients {
		canon[i] = canonicalKey(r.Key)
	}
	sort.Strings(canon)
	sum := sha256.Sum256([]byte(strings.Join(canon, "\n")))
	return fingerprintScheme + ":" + hex.EncodeToString(sum[:])
}
