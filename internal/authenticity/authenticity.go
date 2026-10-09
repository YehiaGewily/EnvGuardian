// Package authenticity creates and verifies detached OpenSSH signatures over
// public ciphertext metadata. It delegates every signature operation to
// ssh-keygen and implements no cryptographic primitive.
package authenticity

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"

	"github.com/YehiaGewily/envguardian/internal/atomic"
	"github.com/YehiaGewily/envguardian/internal/keys"
)

const (
	namespace     = "envguardian"
	payloadDomain = "envguardian-signature-v1"
)

// Binding is the public repository context covered by a ciphertext signature.
type Binding struct {
	RecipientsFingerprint string
	ConfigPath            string
	PlaintextPath         string
	CiphertextPath        string
}

// SignatureError marks present-but-unverifiable authenticity metadata. Its
// message never includes signature bytes, key material, or plaintext data.
type SignatureError struct {
	CiphertextPath string
	Reason         string
	Err            error
}

func (e *SignatureError) Error() string {
	return fmt.Sprintf("ciphertext signature error for %s: %s", e.CiphertextPath, e.Reason)
}

func (e *SignatureError) Unwrap() error { return e.Err }

// SignatureName returns the repository-relative detached signature name.
func SignatureName(ciphertextName string) string {
	return canonicalPath(ciphertextName) + ".sig"
}

// Payload returns the canonical, domain-separated public bytes that are
// signed. Length prefixes prevent path strings from injecting extra fields.
func Payload(binding Binding, ciphertext []byte) []byte {
	digest := sha256.Sum256(ciphertext)
	var out bytes.Buffer
	out.WriteString(payloadDomain)
	out.WriteByte('\n')
	writeField(&out, "ciphertext_sha256", hex.EncodeToString(digest[:]))
	writeField(&out, "recipients_fingerprint", binding.RecipientsFingerprint)
	writeField(&out, "config_path", canonicalPath(binding.ConfigPath))
	writeField(&out, "plaintext_path", canonicalPath(binding.PlaintextPath))
	writeField(&out, "ciphertext_path", canonicalPath(binding.CiphertextPath))
	return out.Bytes()
}

func writeField(out *bytes.Buffer, name, value string) {
	fmt.Fprintf(out, "%s=%d:", name, len([]byte(value)))
	out.WriteString(value)
	out.WriteByte('\n')
}

func canonicalPath(value string) string {
	return path.Clean(strings.ReplaceAll(value, `\`, "/"))
}

// Signer selects the SSH key that ssh-keygen signs with.
type Signer struct {
	// KeyPath is an SSH private-key file, or an SSH public-key file whose
	// private half is held by ssh-agent.
	KeyPath string
	// PublicKey is the signing key's authorized_keys line, used to require that
	// the signer is a current recipient.
	PublicKey string
}

// SignerFromIdentity signs with the SSH private-key file that was resolved as
// the decryption identity. Age identities and raw key material yield a Signer
// that Sign rejects with guidance.
func SignerFromIdentity(identity *keys.Identity) Signer {
	if identity == nil {
		return Signer{}
	}
	return Signer{KeyPath: identity.SSHKeyPath, PublicKey: identity.Recipient}
}

// SignerFromPublicKeyFile signs with an agent-held key named by its public key
// file. It parses only the public key line and never reads private material.
func SignerFromPublicKeyFile(path string) (Signer, error) {
	data, err := os.ReadFile(path) //nolint:gosec // user-selected public key file
	if err != nil {
		return Signer{}, fmt.Errorf("read signing public key: %w", err)
	}
	line := strings.TrimSpace(string(data))
	if first, _, found := strings.Cut(line, "\n"); found {
		line = strings.TrimSpace(first)
	}
	if !strings.HasPrefix(line, "ssh-") {
		return Signer{}, errors.New("signing key must be an SSH public key file (for example ~/.ssh/id_ed25519.pub)")
	}
	if _, err := keys.ParseRecipient(line); err != nil {
		return Signer{}, errors.New("signing key is not a supported SSH public key (ssh-ed25519 or ssh-rsa)")
	}
	return Signer{KeyPath: path, PublicKey: line}, nil
}

// Sign signs the canonical payload with a current SSH recipient's key, either
// from a private-key file or through ssh-agent. ssh-keygen writes only inside a
// fresh temporary directory; the caller places the returned detached signature
// through its managed atomic transaction.
func Sign(signer Signer, recipients *keys.RecipientsFile, binding Binding, ciphertext []byte) ([]byte, string, error) {
	if signer.KeyPath == "" || !strings.HasPrefix(strings.TrimSpace(signer.PublicKey), "ssh-") {
		return nil, "", &SignatureError{CiphertextPath: binding.CiphertextPath, Reason: "sealing requires an SSH key; select a private-key file with --identity or an agent-held public key with --signing-key"}
	}
	name, ok := recipients.RecipientNameForPublicKey(signer.PublicKey)
	if !ok {
		return nil, "", &SignatureError{CiphertextPath: binding.CiphertextPath, Reason: "the signing SSH key is not a current recipient"}
	}
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		return nil, "", &SignatureError{CiphertextPath: binding.CiphertextPath, Reason: "ssh-keygen is unavailable; install OpenSSH", Err: err}
	}
	tempDir, err := os.MkdirTemp("", "envguardian-sign-")
	if err != nil {
		return nil, "", &SignatureError{CiphertextPath: binding.CiphertextPath, Reason: "create temporary signing directory", Err: err}
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	payloadPath := filepath.Join(tempDir, "payload")
	if err := atomic.WriteFile(payloadPath, Payload(binding, ciphertext), 0o600); err != nil {
		return nil, "", &SignatureError{CiphertextPath: binding.CiphertextPath, Reason: "prepare public signing payload", Err: err}
	}
	cmd := exec.Command("ssh-keygen", "-Y", "sign", "-f", signer.KeyPath, "-n", namespace, payloadPath) // #nosec G204 -- fixed binary; arguments are separate
	if _, err := cmd.CombinedOutput(); err != nil {
		return nil, "", &SignatureError{CiphertextPath: binding.CiphertextPath, Reason: "ssh-keygen could not sign with the selected key (for an agent-held key, check that the agent is running and holds it)", Err: err}
	}
	signature, err := os.ReadFile(payloadPath + ".sig") //nolint:gosec // fresh tool-owned temporary path
	if err != nil {
		return nil, "", &SignatureError{CiphertextPath: binding.CiphertextPath, Reason: "read detached signature produced by ssh-keygen", Err: err}
	}
	return signature, name, nil
}

// Verify accepts a signature only when ssh-keygen validates it for one of the
// current recipients' SSH keys. Recipient names never enter allowed-signers
// syntax; synthetic principals prevent repository-controlled name injection.
func Verify(signature []byte, recipients *keys.RecipientsFile, binding Binding, ciphertext []byte) (string, error) {
	if len(bytes.TrimSpace(signature)) == 0 {
		return "", &SignatureError{CiphertextPath: binding.CiphertextPath, Reason: "the detached signature is empty"}
	}
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		return "", &SignatureError{CiphertextPath: binding.CiphertextPath, Reason: "ssh-keygen is unavailable; install OpenSSH", Err: err}
	}
	type candidate struct {
		principal string
		name      string
	}
	var candidates []candidate
	var allowed strings.Builder
	index := 0
	for _, recipient := range recipients.Recipients {
		for _, publicKey := range recipient.PublicKeys() {
			fields := strings.Fields(publicKey)
			if len(fields) < 2 || !strings.HasPrefix(fields[0], "ssh-") {
				continue
			}
			principal := fmt.Sprintf("envguardian-recipient-%d", index)
			fmt.Fprintf(&allowed, "%s %s %s\n", principal, fields[0], fields[1])
			candidates = append(candidates, candidate{principal: principal, name: recipient.Name})
			index++
		}
	}
	if len(candidates) == 0 {
		return "", &SignatureError{CiphertextPath: binding.CiphertextPath, Reason: "no current recipient has an SSH key that can verify signatures"}
	}

	tempDir, err := os.MkdirTemp("", "envguardian-verify-")
	if err != nil {
		return "", &SignatureError{CiphertextPath: binding.CiphertextPath, Reason: "create temporary verification directory", Err: err}
	}
	defer func() { _ = os.RemoveAll(tempDir) }()
	allowedPath := filepath.Join(tempDir, "allowed_signers")
	signaturePath := filepath.Join(tempDir, "ciphertext.sig")
	if err := atomic.WriteFile(allowedPath, []byte(allowed.String()), 0o600); err != nil {
		return "", &SignatureError{CiphertextPath: binding.CiphertextPath, Reason: "prepare current recipient keys", Err: err}
	}
	if err := atomic.WriteFile(signaturePath, signature, 0o600); err != nil {
		return "", &SignatureError{CiphertextPath: binding.CiphertextPath, Reason: "prepare detached signature", Err: err}
	}
	payload := Payload(binding, ciphertext)
	for _, candidate := range candidates {
		cmd := exec.Command("ssh-keygen", "-Y", "verify", "-f", allowedPath, "-I", candidate.principal, "-n", namespace, "-s", signaturePath) // #nosec G204 -- fixed binary; arguments are separate
		cmd.Stdin = bytes.NewReader(payload)
		if err := cmd.Run(); err == nil {
			return candidate.name, nil
		}
	}
	return "", &SignatureError{CiphertextPath: binding.CiphertextPath, Reason: "signature is invalid, incorrectly bound, or was made by a non-recipient"}
}
