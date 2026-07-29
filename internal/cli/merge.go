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

	"github.com/spf13/cobra"

	"github.com/YehiaGewily/envguardian/internal/authenticity"
	"github.com/YehiaGewily/envguardian/internal/config"
	"github.com/YehiaGewily/envguardian/internal/crypt"
	"github.com/YehiaGewily/envguardian/internal/dotenv"
	"github.com/YehiaGewily/envguardian/internal/gitint"
	"github.com/YehiaGewily/envguardian/internal/keys"
)

func newMergeCmd(flags *globalFlags) *cobra.Command {
	var install, continueMerge bool
	cmd := &cobra.Command{
		Use:   "merge",
		Short: "Install or finish the ciphertext merge driver",
		Long: "Install the local ciphertext merge driver, or transactionally finish a paused\n" +
			"merge with --continue. The pause lets EnvGuardian re-sign every resolved\n" +
			"ciphertext and write one complete lock after all per-file decisions succeed.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if install == continueMerge {
				return withExit(exitConfig, errors.New("specify exactly one of --install or --continue"))
			}
			if install {
				return installMergeDriver(cmd, flags)
			}
			return continueCiphertextMerge(cmd, flags)
		},
	}
	cmd.Flags().BoolVar(&install, "install", false, "register the merge drivers in local Git config and .gitattributes")
	cmd.Flags().BoolVar(&continueMerge, "continue", false, "finish a paused merge transaction and stage generated metadata")
	return cmd
}

func newMergeDriverCmd(flags *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:    "merge-driver BASE OURS THEIRS PATH",
		Hidden: true,
		Args:   cobra.ExactArgs(4),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMergeDriver(cmd, flags, args)
		},
	}
}

func newMergeGeneratedDriverCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "merge-generated-driver BASE OURS THEIRS PATH",
		Hidden: true,
		Args:   cobra.ExactArgs(4),
		RunE: func(*cobra.Command, []string) error {
			// Generated signatures and lock state are rebuilt by merge --continue.
			return nil
		},
	}
}

func installMergeDriver(cmd *cobra.Command, flags *globalFlags) error {
	p, err := secureRootPaths(flags)
	if err != nil {
		return err
	}
	root := gitRoot(p.Root)
	lines := []string{
		"*.age -text merge=envguardian",
		"*.age.sig -text merge=envguardian-generated",
		config.Dir + "/" + config.LockFile + " text eol=lf merge=envguardian-generated",
	}
	for _, line := range lines {
		if _, err := gitint.AppendLine(filepath.Join(root, ".gitattributes"), line); err != nil {
			return err
		}
	}
	binary := shellQuote(selfPath())
	if err := gitRun(root, "config", "--local", "merge.envguardian.driver", binary+" merge-driver %O %A %B %P"); err != nil {
		return err
	}
	if err := gitRun(root, "config", "--local", "merge.envguardian.name", "EnvGuardian semantic ciphertext merge"); err != nil {
		return err
	}
	if err := gitRun(root, "config", "--local", "merge.envguardian-generated.driver", binary+" merge-generated-driver %O %A %B %P"); err != nil {
		return err
	}
	fmt.Fprintln(cmd.OutOrStdout(), "configured local EnvGuardian merge drivers")
	fmt.Fprintln(cmd.OutOrStdout(), "commit .gitattributes; successful semantic merges pause for `envguardian merge --continue`")
	return nil
}

func runMergeDriver(cmd *cobra.Command, flags *globalFlags, args []string) error {
	p, err := secureRootPaths(flags)
	if err != nil {
		return err
	}
	cfg, err := loadConfig(p)
	if err != nil {
		return err
	}
	fp, ok := configuredCiphertext(cfg, filepath.ToSlash(args[3]))
	if !ok {
		return withExit(exitConfig, fmt.Errorf("merge path %q is not a configured ciphertext", filepath.ToSlash(args[3])))
	}
	oursPath, err := resolveMergePath(p.Root, args[1])
	if err != nil {
		return withExit(exitConfig, err)
	}
	id, err := keys.ResolveIdentity(flags.identity, keys.DefaultPrompter())
	if err != nil {
		return err
	}
	rf, err := loadRecipients(p)
	if err != nil {
		return err
	}
	recipients, err := rf.AgeRecipients()
	if err != nil {
		return withExit(exitConfig, err)
	}
	base, err := decryptMergeSide(id, args[0], fp.Ciphertext, "base")
	if err != nil {
		return err
	}
	ours, err := decryptMergeSide(id, oursPath, fp.Ciphertext, "ours")
	if err != nil {
		return err
	}
	theirs, err := decryptMergeSide(id, args[2], fp.Ciphertext, "theirs")
	if err != nil {
		return err
	}
	merged, conflicts := gitint.MergeDotenv(base, ours, theirs)
	if len(conflicts) > 0 {
		return mergeConflictError(fp.Ciphertext, conflicts)
	}
	resolved, err := marshalDotenv(merged)
	if err != nil {
		return err
	}
	plan, err := crypt.PlanSealResolvedContent(crypt.Config{
		Identities: id.Identities, Label: id.Label, LockPath: p.Lock, Fingerprint: rf.Fingerprint(),
	}, recipients, resolved, oursPath, fp.Ciphertext)
	if err != nil {
		return err
	}
	if plan.Changed {
		if err := crypt.CommitMergeCiphertext(plan); err != nil {
			return err
		}
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "resolved %s by key; run `envguardian merge --continue` to transactionally re-sign and stage the merge\n", fp.Ciphertext)
	return withExit(exitOutOfSync, errors.New("ciphertext merge intentionally paused for transactional finalization"))
}

func continueCiphertextMerge(cmd *cobra.Command, flags *globalFlags) error {
	p, err := secureRootPaths(flags)
	if err != nil {
		return err
	}
	cfg, err := loadConfig(p)
	if err != nil {
		return err
	}
	if conflict, err := hasUnmergedPath(p.Root, relativeToRoot(p, p.Config)); err != nil || conflict {
		if err != nil {
			return err
		}
		return withExit(exitConfig, errors.New("resolve config.toml before continuing the ciphertext merge"))
	}
	if conflict, err := hasUnmergedPath(p.Root, relativeToRoot(p, p.Recipients)); err != nil || conflict {
		if err != nil {
			return err
		}
		return withExit(exitConfig, errors.New("resolve recipients.toml before continuing the ciphertext merge"))
	}
	rf, err := loadRecipients(p)
	if err != nil {
		return err
	}
	recipients, err := rf.AgeRecipients()
	if err != nil {
		return withExit(exitConfig, err)
	}
	id, err := keys.ResolveIdentity(flags.identity, keys.DefaultPrompter())
	if err != nil {
		return err
	}
	ccfg := crypt.Config{Identities: id.Identities, Label: id.Label, LockPath: p.Lock, Fingerprint: rf.Fingerprint()}
	plans := make([]*crypt.SealPlan, 0, len(cfg.Files))
	for _, fp := range cfg.Files {
		resolved, resolveErr := resolvedMergeContent(p, fp, id, rf)
		if resolveErr != nil {
			return resolveErr
		}
		plan, planErr := crypt.PlanSealResolvedContent(ccfg, recipients, resolved, fp.CiphertextPath, fp.Ciphertext)
		if planErr != nil {
			return planErr
		}
		plans = append(plans, plan)
	}
	additional := make([]*crypt.FilePlan, 0, len(cfg.Files))
	for i, fp := range cfg.Files {
		signaturePlan, signErr := planCiphertextSignature(p, fp, rf.Fingerprint(), rf, id, plans[i])
		if signErr != nil {
			return signErr
		}
		additional = append(additional, signaturePlan)
	}
	if err := crypt.CommitSealPlans(plans, crypt.CommitOptions{
		LockPath: p.Lock, RecipientsFingerprint: rf.Fingerprint(), Additional: additional,
	}); err != nil {
		return err
	}
	stage := []string{"add", "--", relativeToRoot(p, p.Lock)}
	for _, fp := range cfg.Files {
		stage = append(stage, fp.Ciphertext, filepath.ToSlash(fp.Ciphertext+".sig"))
	}
	if err := gitRun(p.Root, stage...); err != nil {
		return err
	}
	fmt.Fprintln(cmd.OutOrStdout(), "finalized, signed, and staged the EnvGuardian merge; review the key names with `envguardian diff` before committing")
	return nil
}

func resolvedMergeContent(p config.Paths, fp config.FilePair, id *keys.Identity, rf *keys.RecipientsFile) ([]byte, error) {
	unmerged, err := hasUnmergedPath(p.Root, fp.Ciphertext)
	if err != nil {
		return nil, err
	}
	if !unmerged {
		data, err := os.ReadFile(fp.CiphertextPath) //nolint:gosec // validated configured path
		if err != nil {
			return nil, fmt.Errorf("read %s while finalizing merge: %w", fp.Ciphertext, err)
		}
		if _, _, err := verifyCiphertextSignature(p, fp, rf, data); err != nil {
			return nil, err
		}
		plaintext, _, err := crypt.DecryptBytesToDotenv(id.Identities, data)
		return plaintext, err
	}
	sides := make([]*dotenv.File, 3)
	for i, stage := range []int{1, 2, 3} {
		data, exists, err := gitStageBlob(p.Root, stage, fp.Ciphertext)
		if err != nil {
			return nil, err
		}
		if !exists {
			continue
		}
		if stage == 2 || stage == 3 {
			ref := "HEAD"
			if stage == 3 {
				ref = "MERGE_HEAD"
			}
			if err := verifyMergeRefSignature(p, fp, ref, rf, data); err != nil {
				return nil, err
			}
		}
		_, sides[i], err = crypt.DecryptBytesToDotenv(id.Identities, data)
		if err != nil {
			return nil, fmt.Errorf("decrypt stage %d of %s: %w", stage, fp.Ciphertext, err)
		}
	}
	merged, conflicts := gitint.MergeDotenv(sides[0], sides[1], sides[2])
	if len(conflicts) > 0 {
		return nil, mergeConflictError(fp.Ciphertext, conflicts)
	}
	if merged == nil {
		return nil, withExit(exitOutOfSync, fmt.Errorf("managed ciphertext %s was deleted; resolve its config mapping explicitly", fp.Ciphertext))
	}
	return marshalDotenv(merged)
}

func verifyMergeRefSignature(p config.Paths, fp config.FilePair, ref string, rf *keys.RecipientsFile, ciphertext []byte) error {
	signaturePath := authenticity.SignatureName(fp.Ciphertext)
	signature, exists, err := gitRefBlob(p.Root, ref, signaturePath)
	if err != nil {
		return err
	}
	if !exists {
		return &authenticity.SignatureError{CiphertextPath: fp.Ciphertext, Reason: fmt.Sprintf("%s side: %s", ref, missingSignatureFailure)}
	}
	binding, err := signatureBinding(p, fp, rf.Fingerprint())
	if err != nil {
		return err
	}
	if _, err := authenticity.Verify(signature, rf, binding, ciphertext); err != nil {
		return fmt.Errorf("authenticate %s side of %s: %w", ref, fp.Ciphertext, err)
	}
	return nil
}

func decryptMergeSide(id *keys.Identity, path, ciphertext, side string) (*dotenv.File, error) {
	data, err := os.ReadFile(path) //nolint:gosec // Git-owned merge temporary path, containment checked for ours
	if err != nil {
		return nil, fmt.Errorf("read %s side of %s: %w", side, ciphertext, err)
	}
	if len(data) == 0 {
		return nil, nil
	}
	_, file, err := crypt.DecryptBytesToDotenv(id.Identities, data)
	if err != nil {
		return nil, fmt.Errorf("decrypt %s side of %s: %w", side, ciphertext, err)
	}
	return file, nil
}

func marshalDotenv(file *dotenv.File) ([]byte, error) {
	var out bytes.Buffer
	if _, err := file.WriteTo(&out); err != nil {
		return nil, fmt.Errorf("serialize merged dotenv: %w", err)
	}
	return out.Bytes(), nil
}

func mergeConflictError(ciphertext string, keys []string) error {
	sort.Strings(keys)
	return withExit(exitOutOfSync, fmt.Errorf("merge conflict in %s for key names: %s", ciphertext, strings.Join(keys, ", ")))
}

func configuredCiphertext(cfg *config.Config, name string) (config.FilePair, bool) {
	want := filepath.ToSlash(filepath.Clean(name))
	for _, fp := range cfg.Files {
		if filepath.ToSlash(filepath.Clean(fp.Ciphertext)) == want {
			return fp, true
		}
	}
	return config.FilePair{}, false
}

func resolveMergePath(root, path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve merge output path: %w", err)
	}
	rel, err := filepath.Rel(root, abs)
	if err != nil || !pathWithinRoot(root, abs) {
		return "", errors.New("git merge output path is outside the repository")
	}
	return config.ResolveManagedPath(root, filepath.ToSlash(rel))
}

func hasUnmergedPath(root, path string) (bool, error) {
	command := exec.Command("git", "ls-files", "-u", "--", filepath.ToSlash(path)) // #nosec G204 -- fixed Git command, path is validated/configured
	command.Dir = root
	output, err := command.Output()
	if err != nil {
		return false, fmt.Errorf("inspect unmerged path %s: %w", path, err)
	}
	return len(output) > 0, nil
}

func gitStageBlob(root string, stage int, path string) ([]byte, bool, error) {
	command := exec.Command("git", "show", fmt.Sprintf(":%d:%s", stage, filepath.ToSlash(path))) // #nosec G204 -- fixed Git command and configured path
	command.Dir = root
	data, err := command.Output()
	if err == nil {
		return data, true, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 128 {
		return nil, false, nil
	}
	return nil, false, fmt.Errorf("read stage %d of %s: %w", stage, path, err)
}

func gitRefBlob(root, ref, path string) ([]byte, bool, error) {
	command := exec.Command("git", "show", ref+":"+filepath.ToSlash(path)) // #nosec G204 -- fixed Git command, fixed ref, and configured path
	command.Dir = root
	data, err := command.Output()
	if err == nil {
		return data, true, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 128 {
		return nil, false, nil
	}
	return nil, false, fmt.Errorf("read %s version of %s: %w", ref, path, err)
}

func relativeToRoot(p config.Paths, path string) string {
	rel, err := filepath.Rel(p.Root, path)
	if err != nil {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(rel)
}
