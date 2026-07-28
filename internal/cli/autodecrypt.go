package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"filippo.io/age"
	"github.com/BurntSushi/toml"
	"github.com/spf13/cobra"

	"github.com/YehiaGewily/envguardian/internal/atomic"
	"github.com/YehiaGewily/envguardian/internal/config"
	"github.com/YehiaGewily/envguardian/internal/crypt"
	"github.com/YehiaGewily/envguardian/internal/gitint"
	"github.com/YehiaGewily/envguardian/internal/keys"
)

const autoDecryptStateVersion = 1

type autoDecryptState struct {
	Version int    `toml:"version"`
	Commit  string `toml:"commit"`
}

type gitBlobResult struct {
	Data   []byte
	Exists bool
}

func newHookAutoDecryptCmd(flags *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:    "hook-auto-decrypt",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runHookAutoDecrypt(cmd, flags)
		},
	}
}

// runHookAutoDecrypt compares security-sensitive blobs before parsing the
// incoming config. Only an unchanged, previously accepted config may select
// destinations for automatic writes.
func runHookAutoDecrypt(cmd *cobra.Command, flags *globalFlags) error {
	p, err := secureRootPaths(flags)
	if err != nil {
		return err
	}
	root := gitRoot(p.Root)
	statePath := p.State
	current, err := resolveCommit(root, "HEAD")
	if err != nil {
		return withExit(exitOutOfSync, fmt.Errorf("automatic decryption blocked: resolve current commit: %w", err))
	}
	state, err := loadAutoDecryptState(statePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return autoDecryptBlocked(root, current, nil, []string{"no previously accepted commit is recorded"})
		}
		return withExit(exitOutOfSync, fmt.Errorf("automatic decryption blocked: read local trust state: %w", err))
	}
	trusted, err := resolveCommit(root, state.Commit)
	if err != nil {
		return autoDecryptBlocked(root, current, nil, []string{"the previously accepted commit is no longer available"})
	}

	configRel, err := repoRelative(root, p.Config)
	if err != nil {
		return withExit(exitConfig, fmt.Errorf("resolve config path: %w", err))
	}
	oldConfig, err := gitBlob(root, trusted, configRel)
	if err != nil {
		return autoDecryptBlocked(root, current, nil, []string{"the accepted commit's managed configuration cannot be read"})
	}
	newConfig, err := gitBlob(root, current, configRel)
	if err != nil {
		return autoDecryptBlocked(root, current, nil, []string{"the incoming commit's managed configuration cannot be read"})
	}
	if !oldConfig.Exists || !newConfig.Exists || !bytes.Equal(oldConfig.Data, newConfig.Data) {
		trustedRecipients := recipientsAtCommit(root, trusted, p)
		return autoDecryptBlocked(root, current, trustedRecipients, []string{"managed configuration changed"})
	}

	// The exact config bytes match the accepted commit, so it is now safe to
	// parse them and resolve managed paths for this repository.
	cfg, err := config.Parse(root, newConfig.Data)
	if err != nil {
		return withExit(exitConfig, fmt.Errorf("automatic decryption blocked: accepted config no longer resolves safely: %w", err))
	}

	trustedRecipients := recipientsAtCommit(root, trusted, p)
	var changes []string
	recipientsRel, relErr := repoRelative(root, p.Recipients)
	if relErr != nil {
		return withExit(exitConfig, fmt.Errorf("resolve recipients path: %w", relErr))
	}
	oldRecipients, oldRecipientsErr := gitBlob(root, trusted, recipientsRel)
	newRecipients, newRecipientsErr := gitBlob(root, current, recipientsRel)
	if oldRecipientsErr != nil || newRecipientsErr != nil || !sameGitBlob(oldRecipients, newRecipients) {
		changes = append(changes, summarizeRecipientChanges(oldRecipients, newRecipients)...)
	}

	var identityErr error
	id, idErr := keys.ResolveIdentity(flags.identity, keys.DefaultPrompter())
	if idErr != nil {
		identityErr = idErr
	}
	for _, fp := range cfg.Files {
		cipherRel, relErr := repoRelative(root, fp.CiphertextPath)
		if relErr != nil {
			return withExit(exitConfig, fmt.Errorf("resolve ciphertext %q: %w", fp.Ciphertext, relErr))
		}
		oldCipher, oldErr := gitBlob(root, trusted, cipherRel)
		newCipher, newErr := gitBlob(root, current, cipherRel)
		if oldErr == nil && newErr == nil && sameGitBlob(oldCipher, newCipher) {
			continue
		}
		if identityErr != nil {
			changes = append(changes, fmt.Sprintf("ciphertext %s changed; key names unavailable without a usable identity", fp.Ciphertext))
			continue
		}
		changes = append(changes, summarizeCiphertextChange(fp.Ciphertext, oldCipher, newCipher, id.Identities))
	}

	if len(changes) > 0 {
		return autoDecryptBlocked(root, current, trustedRecipients, changes)
	}
	if identityErr != nil {
		return identityErr
	}
	if err := ensureAutoDecryptStateIgnored(root); err != nil {
		return err
	}
	if err := decryptCommitSnapshot(root, current, cfg, id, false, cmd); err != nil {
		return err
	}
	if err := saveAutoDecryptState(root, statePath, current); err != nil {
		return err
	}
	return nil
}

// runAcceptChanges is the explicit trust transition. It reads config and
// ciphertext from HEAD, validates and decrypts them, and records HEAD only after
// every plaintext write succeeds.
func runAcceptChanges(cmd *cobra.Command, flags *globalFlags) error {
	p, err := secureRootPaths(flags)
	if err != nil {
		return err
	}
	root := gitRoot(p.Root)
	statePath := p.State
	current, err := resolveCommit(root, "HEAD")
	if err != nil {
		return withExit(exitConfig, fmt.Errorf("--accept-changes requires a committed git snapshot: %w", err))
	}
	configRel, err := repoRelative(root, p.Config)
	if err != nil {
		return withExit(exitConfig, err)
	}
	configBlob, err := gitBlob(root, current, configRel)
	if err != nil || !configBlob.Exists {
		return withExit(exitConfig, fmt.Errorf("read config from commit %s: file is missing", shortCommit(current)))
	}
	cfg, err := config.Parse(root, configBlob.Data)
	if err != nil {
		return withExit(exitConfig, fmt.Errorf("config in commit %s is invalid: %w", shortCommit(current), err))
	}
	id, err := keys.ResolveIdentity(flags.identity, keys.DefaultPrompter())
	if err != nil {
		return err
	}
	if err := ensureAutoDecryptStateIgnored(root); err != nil {
		return err
	}
	if err := decryptCommitSnapshot(root, current, cfg, id, true, cmd); err != nil {
		return err
	}
	if err := saveAutoDecryptState(root, statePath, current); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "accepted managed changes at commit %s\n", shortCommit(current))
	return nil
}

func decryptCommitSnapshot(root, commit string, cfg *config.Config, id *keys.Identity, report bool, cmd *cobra.Command) error {
	for _, fp := range cfg.Files {
		cipherRel, err := repoRelative(root, fp.CiphertextPath)
		if err != nil {
			return withExit(exitConfig, err)
		}
		blob, err := gitBlob(root, commit, cipherRel)
		if err != nil || !blob.Exists {
			return fmt.Errorf("ciphertext %s is missing from commit %s", fp.Ciphertext, shortCommit(commit))
		}
		ccfg := crypt.Config{Identities: id.Identities, Label: id.Label}
		if err := crypt.OpenBytes(ccfg, blob.Data, fp.PlaintextPath); err != nil {
			return fmt.Errorf("refuse to write %s: %w", fp.Plaintext, err)
		}
		if report {
			fmt.Fprintf(cmd.OutOrStdout(), "decrypted %s → %s\n", fp.Ciphertext, fp.Plaintext)
		}
	}
	return nil
}

func loadAutoDecryptState(path string) (*autoDecryptState, error) {
	data, err := os.ReadFile(path) //nolint:gosec // fixed local state path
	if err != nil {
		return nil, err
	}
	var state autoDecryptState
	if err := toml.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if state.Version != autoDecryptStateVersion || !validObjectID(state.Commit) {
		return nil, fmt.Errorf("unsupported or incomplete automatic-decryption state")
	}
	return &state, nil
}

func saveAutoDecryptState(root, statePath, commit string) error {
	if err := ensureAutoDecryptStateIgnored(root); err != nil {
		return err
	}
	var out strings.Builder
	if err := toml.NewEncoder(&out).Encode(autoDecryptState{Version: autoDecryptStateVersion, Commit: commit}); err != nil {
		return fmt.Errorf("encode automatic-decryption state: %w", err)
	}
	if err := atomic.WriteFile(statePath, []byte(out.String()), 0o600); err != nil {
		return fmt.Errorf("write automatic-decryption state: %w", err)
	}
	return nil
}

func ensureAutoDecryptStateIgnored(root string) error {
	ignored, err := gitint.IsIgnored(root, config.AutoDecryptStateRelative)
	if err != nil {
		return fmt.Errorf("verify automatic-decryption state is gitignored: %w", err)
	}
	if !ignored {
		return fmt.Errorf("refusing to write local trust state: %s is not gitignored; run `envguardian install-hooks`", config.AutoDecryptStateRelative)
	}
	return nil
}

func autoDecryptBlocked(root, current string, trustedRecipients *keys.RecipientsFile, changes []string) error {
	sort.Strings(changes)
	var message strings.Builder
	fmt.Fprintf(&message, "automatic decryption blocked for commit %s:\n", shortCommit(current))
	for _, change := range changes {
		fmt.Fprintf(&message, "  - %s\n", change)
	}
	fmt.Fprintf(&message, "  - %s\n", signatureDiagnostic(root, current, trustedRecipients))
	message.WriteString("review the commit, then run `envguardian decrypt --accept-changes` to allow these managed changes")
	return withExit(exitOutOfSync, errors.New(message.String()))
}

func recipientsAtCommit(root, commit string, p config.Paths) *keys.RecipientsFile {
	rel, err := repoRelative(root, p.Recipients)
	if err != nil {
		return nil
	}
	blob, err := gitBlob(root, commit, rel)
	if err != nil || !blob.Exists {
		return nil
	}
	rf, err := keys.ParseRecipients(blob.Data)
	if err != nil {
		return nil
	}
	return rf
}

func summarizeRecipientChanges(oldBlob, newBlob gitBlobResult) []string {
	if !oldBlob.Exists || !newBlob.Exists {
		return []string{"recipients changed; recipient names are unavailable because the file was added or removed"}
	}
	oldFile, oldErr := keys.ParseRecipients(oldBlob.Data)
	newFile, newErr := keys.ParseRecipients(newBlob.Data)
	if oldErr != nil || newErr != nil {
		return []string{"recipients changed; recipient names are unavailable because the file is malformed"}
	}
	oldByName := make(map[string]keys.Recipient, len(oldFile.Recipients))
	newByName := make(map[string]keys.Recipient, len(newFile.Recipients))
	for _, recipient := range oldFile.Recipients {
		oldByName[recipient.Name] = recipient
	}
	for _, recipient := range newFile.Recipients {
		newByName[recipient.Name] = recipient
	}
	var result []string
	for name, oldRecipient := range oldByName {
		newRecipient, ok := newByName[name]
		switch {
		case !ok:
			result = append(result, fmt.Sprintf("recipient removed: %s", name))
		case !recipientKeysEqual(oldRecipient, newRecipient):
			result = append(result, fmt.Sprintf("recipient key changed: %s", name))
		}
	}
	for name := range newByName {
		if _, ok := oldByName[name]; !ok {
			result = append(result, fmt.Sprintf("recipient added: %s", name))
		}
	}
	if len(result) == 0 {
		result = append(result, "recipient metadata changed")
	}
	sort.Strings(result)
	return result
}

func recipientKeysEqual(a, b keys.Recipient) bool {
	left := append([]string(nil), a.PublicKeys()...)
	right := append([]string(nil), b.PublicKeys()...)
	for i := range left {
		left[i] = strings.TrimSpace(left[i])
	}
	for i := range right {
		right[i] = strings.TrimSpace(right[i])
	}
	sort.Strings(left)
	sort.Strings(right)
	return len(left) == len(right) && strings.Join(left, "\x00") == strings.Join(right, "\x00")
}

func summarizeCiphertextChange(name string, oldBlob, newBlob gitBlobResult, identities []age.Identity) string {
	var keyChanges []string
	switch {
	case !oldBlob.Exists && newBlob.Exists:
		_, current, err := crypt.DecryptBytesToDotenv(identities, newBlob.Data)
		if err != nil {
			return fmt.Sprintf("ciphertext %s changed; key names could not be inspected safely", name)
		}
		for _, key := range current.Keys() {
			keyChanges = append(keyChanges, "+ "+key)
		}
	case oldBlob.Exists && !newBlob.Exists:
		_, previous, err := crypt.DecryptBytesToDotenv(identities, oldBlob.Data)
		if err != nil {
			return fmt.Sprintf("ciphertext %s changed; key names could not be inspected safely", name)
		}
		for _, key := range previous.Keys() {
			keyChanges = append(keyChanges, "- "+key)
		}
	case oldBlob.Exists && newBlob.Exists:
		_, previous, oldErr := crypt.DecryptBytesToDotenv(identities, oldBlob.Data)
		_, current, newErr := crypt.DecryptBytesToDotenv(identities, newBlob.Data)
		if oldErr != nil || newErr != nil {
			return fmt.Sprintf("ciphertext %s changed; key names could not be inspected safely", name)
		}
		added, removed, changed := diffKeys(previous, current)
		for _, key := range added {
			keyChanges = append(keyChanges, "+ "+key)
		}
		for _, key := range removed {
			keyChanges = append(keyChanges, "- "+key)
		}
		for _, key := range changed {
			keyChanges = append(keyChanges, "~ "+key)
		}
	default:
		return fmt.Sprintf("ciphertext %s changed; file is unavailable in both commits", name)
	}
	sort.Strings(keyChanges)
	if len(keyChanges) == 0 {
		return fmt.Sprintf("ciphertext %s changed; no key-name changes detected", name)
	}
	return fmt.Sprintf("ciphertext %s changed keys: %s", name, strings.Join(keyChanges, ", "))
}

func sameGitBlob(a, b gitBlobResult) bool {
	return a.Exists == b.Exists && (!a.Exists || bytes.Equal(a.Data, b.Data))
}

func resolveCommit(root, revision string) (string, error) {
	out, err := gitCommandBytes(root, "rev-parse", "--verify", revision+"^{commit}")
	if err != nil {
		return "", err
	}
	commit := strings.TrimSpace(string(out))
	if commit == "" {
		return "", errors.New("git returned an empty commit id")
	}
	return commit, nil
}

func gitBlob(root, commit, rel string) (gitBlobResult, error) {
	out, err := gitCommandBytes(root, "show", commit+":"+filepath.ToSlash(rel))
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return gitBlobResult{}, nil
		}
		return gitBlobResult{}, err
	}
	return gitBlobResult{Data: out, Exists: true}, nil
}

func gitCommandBytes(root string, args ...string) ([]byte, error) {
	cmd := exec.Command("git", args...) // #nosec G204 -- fixed binary; arguments are separate, never a shell command
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return out, nil
}

func repoRelative(root, target string) (string, error) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	rootResolved, err := filepath.EvalSymlinks(rootAbs)
	if err != nil {
		return "", err
	}
	targetAbs, err := filepath.Abs(target)
	if err != nil {
		return "", err
	}
	// A target spelled through a symlinked root first needs the same canonical
	// resolution used by config loading. Already-resolved managed paths take the
	// second branch and are compared directly with rootResolved.
	if lexicalRel, relErr := filepath.Rel(rootAbs, targetAbs); relErr == nil && pathIsContained(lexicalRel) {
		targetAbs, err = config.ResolveManagedPath(rootAbs, filepath.ToSlash(lexicalRel))
		if err != nil {
			return "", err
		}
	}
	rel, err := filepath.Rel(rootResolved, targetAbs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("path %s is outside repository %s", target, root)
	}
	return filepath.ToSlash(rel), nil
}

func pathIsContained(rel string) bool {
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

func signatureDiagnostic(root, commit string, trustedRecipients *keys.RecipientsFile) string {
	raw, err := gitCommandBytes(root, "cat-file", "commit", commit)
	if err != nil {
		return fmt.Sprintf("incoming commit %s signature could not be inspected", shortCommit(commit))
	}
	header := raw
	if split := bytes.Index(raw, []byte("\n\n")); split >= 0 {
		header = raw[:split]
	}
	if !bytes.HasPrefix(header, []byte("gpgsig ")) && !bytes.Contains(header, []byte("\ngpgsig ")) {
		return fmt.Sprintf("incoming commit %s is unsigned", shortCommit(commit))
	}
	verification, err := gitCommandBytes(root, "show", "-s", "--format=%G?%x00%GK", commit)
	if err != nil {
		return fmt.Sprintf("incoming commit %s is signed, but its signer could not be verified as a recipient", shortCommit(commit))
	}
	parts := bytes.SplitN(bytes.TrimSpace(verification), []byte{0}, 2)
	status := ""
	fingerprint := ""
	if len(parts) > 0 {
		status = string(parts[0])
	}
	if len(parts) == 2 {
		fingerprint = string(parts[1])
	}
	if (status == "G" || status == "U") && trustedRecipients != nil {
		if name, ok := trustedRecipients.RecipientNameForSigningKey(fingerprint); ok {
			return fmt.Sprintf("incoming commit %s is signed by recipient %q", shortCommit(commit), name)
		}
	}
	if status == "G" || status == "U" {
		return fmt.Sprintf("incoming commit %s is signed by a non-recipient", shortCommit(commit))
	}
	return fmt.Sprintf("incoming commit %s is signed, but its signer could not be verified as a recipient", shortCommit(commit))
}

func shortCommit(commit string) string {
	if len(commit) > 12 {
		return commit[:12]
	}
	return commit
}

func validObjectID(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, r := range value {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}
