package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/YehiaGewily/envguardian/internal/authenticity"
	"github.com/YehiaGewily/envguardian/internal/config"
	"github.com/YehiaGewily/envguardian/internal/crypt"
	"github.com/YehiaGewily/envguardian/internal/keys"
)

func newDecryptCmd(flags *globalFlags) *cobra.Command {
	var acceptChanges bool
	cmd := &cobra.Command{
		Use:   "decrypt",
		Short: "Decrypt every ciphertext file to its plaintext (mode 0600)",
		Long: "Inside a Git work tree, decrypt installs only the committed HEAD snapshot, and only\n" +
			"when its config, recipients, ciphertext, and signatures are identical to the commit\n" +
			"you last accepted. Otherwise it writes nothing and lists the changed key and recipient\n" +
			"names; review the commit, then run `decrypt --accept-changes`. Outside a Git repository\n" +
			"it decrypts the files on disk.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runDecrypt(cmd, flags, acceptChanges)
		},
	}
	cmd.Flags().BoolVar(&acceptChanges, "accept-changes", false, "accept the current commit's managed inputs and update automatic-decryption trust state")
	return cmd
}

func runDecrypt(cmd *cobra.Command, flags *globalFlags, acceptChanges bool) error {
	if acceptChanges {
		return runAcceptChanges(cmd, flags)
	}
	p, err := secureRootPaths(flags)
	if err != nil {
		return err
	}
	root, inRepo, err := gitWorkTree(p.Root)
	if err != nil {
		return err
	}
	if inRepo {
		return runDecryptAccepted(cmd, flags, p, root)
	}
	return runDecryptWorkingTree(cmd, flags, p)
}

// runDecryptAccepted is plain `decrypt` inside a Git work tree. It applies the
// same trust gate as the post-checkout and post-merge hook, so HEAD's config,
// recipients, ciphertext, and signatures must be identical to the locally
// accepted commit, and it decrypts only HEAD's committed blobs. It never
// records trust state; only `decrypt --accept-changes` and an unchanged hook
// run do.
func runDecryptAccepted(cmd *cobra.Command, flags *globalFlags, p config.Paths, root string) error {
	accepted, err := compareWithAcceptedCommit(root, p, flags, "decryption")
	if err != nil {
		return err
	}
	keep, err := reviewUncommittedManagedFiles(root, p, accepted)
	if err != nil {
		return err
	}
	return decryptCommitSnapshot(root, accepted.commit, p, accepted.cfg, accepted.id, true, keep, cmd)
}

// runDecryptWorkingTree decrypts the files on disk. It is used only outside a
// Git repository, where there is no branch to receive and no commit to accept.
func runDecryptWorkingTree(cmd *cobra.Command, flags *globalFlags, p config.Paths) error {
	cfg, err := loadConfig(p)
	if err != nil {
		return err
	}

	id, err := keys.ResolveIdentity(flags.identity, keys.DefaultPrompter())
	if err != nil {
		return err // *NoIdentityError → exit 2
	}

	ccfg := crypt.Config{Identities: id.Identities, Label: id.Label}
	rf, err := loadRecipients(p)
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	for _, fp := range cfg.Files {
		ciphertext, readErr := os.ReadFile(fp.CiphertextPath) //nolint:gosec // validated managed ciphertext path
		if readErr != nil {
			return fmt.Errorf("read ciphertext %s: %w", fp.Ciphertext, readErr)
		}
		signer, _, verifyErr := verifyCiphertextSignature(p, fp, rf, ciphertext)
		if verifyErr != nil {
			return verifyErr
		}
		if flags.verbose {
			fmt.Fprintf(cmd.ErrOrStderr(), "envguardian: verbose: signature for %s verified as recipient %q\n", fp.Ciphertext, signer)
		}
		if err := crypt.Open(ccfg, fp.CiphertextPath, fp.PlaintextPath); err != nil {
			return err // ErrNotARecipient → exit 2
		}
		fmt.Fprintf(out, "decrypted %s → %s\n", fp.Ciphertext, fp.Plaintext)
	}
	return nil
}

// gitWorkTree reports the top level of the Git work tree containing dir.
// Outside any repository it returns inRepo=false. When Git cannot answer but
// GIT_DIR or a .git entry at or above dir says this is a repository, it fails
// closed: treating a Git failure as "not a repository" would skip the trust
// check.
func gitWorkTree(dir string) (root string, inRepo bool, err error) {
	out, gitErr := gitCommandBytes(dir, "rev-parse", "--show-toplevel")
	if gitErr == nil {
		if top := strings.TrimSpace(string(out)); top != "" {
			return top, true, nil
		}
		gitErr = errors.New("git returned an empty work-tree path")
	}
	marker := "GIT_DIR"
	if os.Getenv("GIT_DIR") == "" {
		marker = findGitEntry(dir)
	}
	if marker == "" {
		return "", false, nil
	}
	return "", false, withExit(exitOutOfSync, fmt.Errorf(
		"decryption blocked: %s indicates a Git repository, but Git could not open it (%w); "+
			"decrypt checks accepted trust state through Git, so fix the repository or Git installation and retry",
		marker, gitErr))
}

// findGitEntry returns the first .git file or directory at or above dir. An
// entry that cannot be inspected counts as present.
func findGitEntry(dir string) string {
	for current := dir; ; {
		candidate := filepath.Join(current, ".git")
		if _, err := os.Lstat(candidate); err == nil || !errors.Is(err, os.ErrNotExist) {
			return candidate
		}
		parent := filepath.Dir(current)
		if parent == current {
			return ""
		}
		current = parent
	}
}

// reviewUncommittedManagedFiles compares the working tree's managed files with
// HEAD. Plain decrypt reads only HEAD, so an uncommitted file can never supply
// plaintext; this check stops decrypt from silently replacing a developer's
// newer local plaintext with HEAD's older values. Uncommitted config or
// recipients changes always refuse. An uncommitted ciphertext or signature is
// tolerated only when it verifies against HEAD's recipients and decrypts to
// exactly the bytes already in its plaintext file, so leaving that file
// untouched changes nothing; those pairs are returned by ciphertext name. Any
// other difference refuses before a plaintext write.
func reviewUncommittedManagedFiles(root string, p config.Paths, accepted *acceptedSnapshot) (map[string]bool, error) {
	configRel, err := repoRelative(root, p.Config)
	if err != nil {
		return nil, withExit(exitConfig, fmt.Errorf("resolve config path: %w", err))
	}
	recipientsRel, err := repoRelative(root, p.Recipients)
	if err != nil {
		return nil, withExit(exitConfig, fmt.Errorf("resolve recipients path: %w", err))
	}
	type managedPair struct {
		pair                    config.FilePair
		cipherRel, signatureRel string
	}
	pairs := make([]managedPair, 0, len(accepted.cfg.Files))
	paths := []string{configRel, recipientsRel}
	for _, fp := range accepted.cfg.Files {
		cipherRel, relErr := repoRelative(root, fp.CiphertextPath)
		if relErr != nil {
			return nil, withExit(exitConfig, fmt.Errorf("resolve ciphertext %q: %w", fp.Ciphertext, relErr))
		}
		pair := managedPair{pair: fp, cipherRel: cipherRel, signatureRel: authenticity.SignatureName(cipherRel)}
		pairs = append(pairs, pair)
		paths = append(paths, pair.cipherRel, pair.signatureRel)
	}
	dirty, err := uncommittedPaths(root, paths)
	if err != nil {
		return nil, withExit(exitOutOfSync, fmt.Errorf("decryption blocked: compare managed files with commit %s: %w", shortCommit(accepted.commit), err))
	}
	if len(dirty) == 0 {
		return nil, nil
	}

	var problems []string
	if dirty[configRel] || dirty[recipientsRel] {
		// An uncommitted signature would be checked against HEAD's mapping and
		// recipients, which are themselves being changed; report every path.
		for _, rel := range paths {
			if dirty[rel] {
				problems = append(problems, fmt.Sprintf("%s has uncommitted changes", rel))
			}
		}
		return nil, uncommittedBlocked(accepted.commit, problems)
	}
	rf := recipientsAtCommit(root, accepted.commit, p)
	if rf == nil {
		return nil, withExit(exitConfig, fmt.Errorf("recipients file in commit %s is missing or invalid", shortCommit(accepted.commit)))
	}
	keep := make(map[string]bool)
	for _, mp := range pairs {
		if !dirty[mp.cipherRel] && !dirty[mp.signatureRel] {
			continue
		}
		matches, problem, err := uncommittedCiphertextMatches(root, p, accepted, rf, mp.pair, mp.cipherRel)
		if err != nil {
			return nil, err
		}
		if matches {
			keep[mp.pair.Ciphertext] = true
		} else {
			problems = append(problems, problem)
		}
	}
	if len(problems) > 0 {
		return nil, uncommittedBlocked(accepted.commit, problems)
	}
	return keep, nil
}

// uncommittedCiphertextMatches reports whether a pair's working-tree
// ciphertext verifies against HEAD's recipients and decrypts to exactly the
// bytes in its plaintext file. A failed signature check is an error, not a
// mismatch. The returned problem names keys only.
func uncommittedCiphertextMatches(root string, p config.Paths, accepted *acceptedSnapshot, rf *keys.RecipientsFile, fp config.FilePair, cipherRel string) (bool, string, error) {
	working, err := os.ReadFile(fp.CiphertextPath) //nolint:gosec // validated managed ciphertext path
	if errors.Is(err, os.ErrNotExist) {
		return false, fmt.Sprintf("%s is deleted in the working tree", fp.Ciphertext), nil
	}
	if err != nil {
		return false, "", fmt.Errorf("read ciphertext %s: %w", fp.Ciphertext, err)
	}
	if _, _, err := verifyCiphertextSignature(p, fp, rf, working); err != nil {
		return false, "", err
	}
	plaintext, _, err := crypt.DecryptBytesToDotenv(accepted.id.Identities, working)
	if err != nil {
		return false, "", fmt.Errorf("decrypt uncommitted %s: %w", fp.Ciphertext, err)
	}
	local, localErr := os.ReadFile(fp.PlaintextPath) //nolint:gosec // validated managed plaintext path
	if localErr == nil && bytes.Equal(plaintext, local) {
		return true, "", nil
	}
	if localErr != nil && !errors.Is(localErr, os.ErrNotExist) {
		return false, "", fmt.Errorf("read plaintext %s: %w", fp.Plaintext, localErr)
	}
	headBlob, err := gitBlob(root, accepted.commit, cipherRel)
	if err != nil {
		return false, "", withExit(exitOutOfSync, fmt.Errorf("decryption blocked: read %s from commit %s: %w", fp.Ciphertext, shortCommit(accepted.commit), err))
	}
	summary := summarizeCiphertextChange(fp.Ciphertext, headBlob, gitBlobResult{Data: working, Exists: true}, accepted.id.Identities)
	if errors.Is(localErr, os.ErrNotExist) {
		return false, fmt.Sprintf("uncommitted %s; local %s is missing", summary, fp.Plaintext), nil
	}
	return false, fmt.Sprintf("uncommitted %s; local %s does not match it", summary, fp.Plaintext), nil
}

// uncommittedPaths returns which of paths differ between HEAD and the working
// tree as Git compares them, after its line-ending normalization. A path absent
// from HEAD is not reported; decryptCommitSnapshot refuses that pair anyway.
func uncommittedPaths(root string, paths []string) (map[string]bool, error) {
	args := []string{"--literal-pathspecs", "diff", "--no-ext-diff", "--no-textconv", "--no-renames", "--name-only", "-z", "HEAD", "--"}
	out, err := gitCommandBytes(root, append(args, paths...)...)
	if err != nil {
		return nil, err
	}
	dirty := make(map[string]bool)
	for _, name := range bytes.Split(out, []byte{0}) {
		if len(name) > 0 {
			dirty[string(name)] = true
		}
	}
	return dirty, nil
}

func uncommittedBlocked(commit string, problems []string) error {
	sort.Strings(problems)
	var message strings.Builder
	fmt.Fprintf(&message, "decryption blocked: managed files differ from commit %s:\n", shortCommit(commit))
	for _, problem := range problems {
		fmt.Fprintf(&message, "  - %s\n", problem)
	}
	message.WriteString("decrypt installs only the committed, accepted snapshot and will not replace newer local plaintext with it\n")
	message.WriteString("if you made these changes, commit them and run `envguardian decrypt --accept-changes`; " +
		"otherwise review them and restore the committed files with `git restore --source=HEAD --staged --worktree -- <path>`")
	return withExit(exitOutOfSync, errors.New(message.String()))
}
