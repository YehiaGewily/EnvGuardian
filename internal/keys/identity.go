package keys

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"filippo.io/age/armor"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// Reason is a typed enumeration of why one identity source was rejected. Tests
// and --json output assert on these constants rather than the rendered message.
type Reason string

const (
	ReasonNotProvided     Reason = "not provided"
	ReasonNotFound        Reason = "not found"
	ReasonUnreadable      Reason = "unreadable"
	ReasonBadPassphrase   Reason = "bad passphrase"
	ReasonNeedsPassphrase Reason = "encrypted, and no TTY is attached"
	ReasonMalformed       Reason = "not a valid age or SSH key"
)

// ErrPassphraseRequired is returned when an identity is passphrase-protected but
// no terminal is attached to prompt for it. It is reachable via errors.Is
// through NoIdentityError so the CLI can map it to exit code 2 with guidance.
var ErrPassphraseRequired = errors.New("identity is passphrase-protected but no terminal is attached to prompt for it")

// Attempt records one identity source and why it was rejected.
type Attempt struct {
	Source string
	Reason Reason
	Err    error // underlying cause, if any
}

// NoIdentityError is returned when every source in the resolution chain failed.
// Its message lists every source tried, in order, with the reason each was
// rejected and the next step.
type NoIdentityError struct {
	Attempts []Attempt
}

func (e *NoIdentityError) Error() string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "no usable identity found; tried %d sources:\n", len(e.Attempts))
	width := 0
	for _, a := range e.Attempts {
		if len(a.Source) > width {
			width = len(a.Source)
		}
	}
	for _, a := range e.Attempts {
		reason := string(a.Reason)
		if a.Err != nil && a.Reason != ReasonNeedsPassphrase {
			reason = fmt.Sprintf("%s (%v)", a.Reason, a.Err)
		}
		fmt.Fprintf(&b, "  %-*s  %s\n", width, a.Source, reason)
	}
	b.WriteString("next: set $ENVGUARDIAN_IDENTITY to your key (path or contents), or pass --identity <path>")
	return b.String()
}

// Unwrap exposes the underlying errors so errors.Is can find, e.g.,
// ErrPassphraseRequired.
func (e *NoIdentityError) Unwrap() []error {
	var errs []error
	for _, a := range e.Attempts {
		if a.Err != nil {
			errs = append(errs, a.Err)
		}
	}
	return errs
}

// Identity is a resolved decryption identity: one or more age identities parsed
// from a single source, a human label naming that source for messages, and the
// corresponding public key (used by `init` to seed recipients.toml).
type Identity struct {
	Identities []age.Identity
	Label      string
	Recipient  string // public key line: "age1..." or "ssh-ed25519 ..."
}

// Prompter supplies passphrases for encrypted identities. Interactive reports
// whether prompting is even possible (a TTY exists), so resolution can fail
// cleanly instead of hanging.
type Prompter interface {
	Interactive() bool
	Passphrase(prompt string) ([]byte, error)
}

type terminalPrompter struct{}

func (terminalPrompter) Interactive() bool { return term.IsTerminal(int(os.Stdin.Fd())) }

func (terminalPrompter) Passphrase(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	return pw, err
}

// DefaultPrompter reads passphrases from the controlling terminal.
func DefaultPrompter() Prompter { return terminalPrompter{} }

// ResolveIdentity walks the resolution chain and returns the first usable
// identity. On total failure it returns a *NoIdentityError listing every source
// tried and why it was rejected.
//
// Order: --identity flag → $ENVGUARDIAN_IDENTITY (path or raw material) →
// ~/.config/envguardian/identity.txt → ~/.ssh/id_ed25519 → ~/.ssh/id_rsa. An
// explicitly supplied flag or environment value is authoritative: if invalid,
// resolution fails instead of silently falling through to another identity.
func ResolveIdentity(flagPath string, p Prompter) (*Identity, error) {
	if p == nil {
		p = DefaultPrompter()
	}
	home, _ := os.UserHomeDir()

	type source struct {
		name string
		get  func() (raw []byte, label string, reason Reason)
	}
	sources := []source{
		{"--identity flag", func() ([]byte, string, Reason) {
			if flagPath == "" {
				return nil, "", ReasonNotProvided
			}
			return readMaybe(flagPath)
		}},
		{"$ENVGUARDIAN_IDENTITY", func() ([]byte, string, Reason) {
			v := os.Getenv("ENVGUARDIAN_IDENTITY")
			if v == "" {
				return nil, "", ReasonNotProvided
			}
			if fi, err := os.Stat(v); err == nil && !fi.IsDir() { //nolint:gosec // G703: $ENVGUARDIAN_IDENTITY may be a path; that is the intended check
				raw, label, reason := readMaybe(v)
				return raw, label, reason
			}
			// Raw key material (the CI path).
			return []byte(v), "$ENVGUARDIAN_IDENTITY", ""
		}},
		{"~/.config/envguardian/identity.txt", func() ([]byte, string, Reason) {
			if home == "" {
				return nil, "", ReasonNotFound
			}
			return readMaybe(filepath.Join(home, ".config", "envguardian", "identity.txt"))
		}},
		{"~/.ssh/id_ed25519", func() ([]byte, string, Reason) {
			if home == "" {
				return nil, "", ReasonNotFound
			}
			return readMaybe(filepath.Join(home, ".ssh", "id_ed25519"))
		}},
		{"~/.ssh/id_rsa", func() ([]byte, string, Reason) {
			if home == "" {
				return nil, "", ReasonNotFound
			}
			return readMaybe(filepath.Join(home, ".ssh", "id_rsa"))
		}},
	}

	var attempts []Attempt
	for _, s := range sources {
		authoritative := (s.name == "--identity flag" && flagPath != "") ||
			(s.name == "$ENVGUARDIAN_IDENTITY" && os.Getenv("ENVGUARDIAN_IDENTITY") != "")
		raw, label, reason := s.get()
		if raw == nil {
			attempts = append(attempts, Attempt{Source: s.name, Reason: reason})
			if authoritative {
				return nil, &NoIdentityError{Attempts: attempts}
			}
			continue
		}
		ids, recipient, err := parseIdentities(raw, p)
		if err != nil {
			attempts = append(attempts, Attempt{Source: s.name, Reason: reasonForErr(err), Err: err})
			if authoritative {
				return nil, &NoIdentityError{Attempts: attempts}
			}
			continue
		}
		return &Identity{Identities: ids, Label: label, Recipient: recipient}, nil
	}
	return nil, &NoIdentityError{Attempts: attempts}
}

// readMaybe reads a file, returning a reason instead of bytes if it is missing
// or unreadable. On success the label is the path.
func readMaybe(path string) ([]byte, string, Reason) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: identity path from the resolution chain
	if err != nil {
		if os.IsNotExist(err) {
			return nil, "", ReasonNotFound
		}
		return nil, "", ReasonUnreadable
	}
	return data, path, ""
}

func reasonForErr(err error) Reason {
	switch {
	case errors.Is(err, ErrPassphraseRequired):
		return ReasonNeedsPassphrase
	default:
		return ReasonMalformed
	}
}

// parseIdentities parses raw key material, transparently handling SSH private
// keys (encrypted or not) and age identities (plain or passphrase-protected). It
// also returns the public key line for the identity, for `init` seeding.
func parseIdentities(raw []byte, p Prompter) ([]age.Identity, string, error) {
	trimmed := bytes.TrimSpace(raw)
	switch {
	case isSSHPrivateKey(trimmed):
		return parseSSHIdentity(raw, p)
	case isAgeEncrypted(trimmed):
		return parseEncryptedAgeIdentity(raw, p)
	default:
		ids, err := age.ParseIdentities(bytes.NewReader(raw))
		if err != nil {
			return nil, "", err
		}
		return ids, ageRecipientString(ids), nil
	}
}

func parseSSHIdentity(pem []byte, p Prompter) ([]age.Identity, string, error) {
	id, err := agessh.ParseIdentity(pem)
	if err == nil {
		recipient := ""
		if signer, serr := ssh.ParsePrivateKey(pem); serr == nil {
			recipient = sshRecipientString(signer.PublicKey())
		}
		return []age.Identity{id}, recipient, nil
	}
	var missing *ssh.PassphraseMissingError
	if !errors.As(err, &missing) {
		return nil, "", err
	}
	if !p.Interactive() {
		return nil, "", ErrPassphraseRequired
	}
	if missing.PublicKey == nil {
		return nil, "", fmt.Errorf("encrypted SSH key has no embedded public key; convert it to the OpenSSH format or use an age key: %w", err)
	}
	enc, err := agessh.NewEncryptedSSHIdentity(missing.PublicKey, pem, func() ([]byte, error) {
		return p.Passphrase("Enter passphrase for SSH key: ")
	})
	if err != nil {
		return nil, "", err
	}
	return []age.Identity{enc}, sshRecipientString(missing.PublicKey), nil
}

func parseEncryptedAgeIdentity(raw []byte, p Prompter) ([]age.Identity, string, error) {
	if !p.Interactive() {
		return nil, "", ErrPassphraseRequired
	}
	pass, err := p.Passphrase("Enter passphrase for age identity: ")
	if err != nil {
		return nil, "", err
	}
	scrypt, err := age.NewScryptIdentity(string(pass))
	if err != nil {
		return nil, "", err
	}
	var src io.Reader = bytes.NewReader(raw)
	if isArmored(raw) {
		src = armor.NewReader(src)
	}
	r, err := age.Decrypt(src, scrypt)
	if err != nil {
		return nil, "", fmt.Errorf("decrypt passphrase-protected age identity (wrong passphrase?): %w", err)
	}
	dec, err := io.ReadAll(r)
	if err != nil {
		return nil, "", err
	}
	ids, err := age.ParseIdentities(bytes.NewReader(dec))
	if err != nil {
		return nil, "", err
	}
	return ids, ageRecipientString(ids), nil
}

// ageRecipientString returns the age1... recipient for the first X25519 identity.
func ageRecipientString(ids []age.Identity) string {
	for _, id := range ids {
		if x, ok := id.(*age.X25519Identity); ok {
			return x.Recipient().String()
		}
	}
	return ""
}

func sshRecipientString(pub ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
}

func isSSHPrivateKey(b []byte) bool {
	return bytes.HasPrefix(b, []byte("-----BEGIN ")) && bytes.Contains(b, []byte("PRIVATE KEY-----"))
}

func isAgeEncrypted(b []byte) bool {
	return bytes.HasPrefix(b, []byte("age-encryption.org/v1")) ||
		bytes.HasPrefix(b, []byte(armor.Header))
}

func isArmored(b []byte) bool {
	return bytes.HasPrefix(bytes.TrimSpace(b), []byte(armor.Header))
}
