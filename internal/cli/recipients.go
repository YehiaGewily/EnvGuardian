package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/YehiaGewily/envguardian/internal/crypt"
	"github.com/YehiaGewily/envguardian/internal/gitint"
	"github.com/YehiaGewily/envguardian/internal/keys"
)

func newAddRecipientCmd(flags *globalFlags) *cobra.Command {
	var github, key, sshPath, name string
	cmd := &cobra.Command{
		Use:   "add-recipient",
		Short: "Add a recipient and re-encrypt to the new set",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runAddRecipient(cmd, flags, github, key, sshPath, name)
		},
	}
	cmd.Flags().StringVar(&github, "github", "", "fetch the recipient's ed25519 key from github.com/<user>.keys")
	cmd.Flags().StringVar(&key, "key", "", "recipient public key (age1... or ssh-ed25519 ...)")
	cmd.Flags().StringVar(&sshPath, "ssh", "", "path to a recipient's SSH public key file")
	cmd.Flags().StringVar(&name, "name", "", "recipient name (defaults to the GitHub username)")
	return cmd
}

func runAddRecipient(cmd *cobra.Command, flags *globalFlags, github, key, sshPath, name string) error {
	p, err := secureRootPaths(flags)
	if err != nil {
		return err
	}
	cfg, err := loadConfig(p)
	if err != nil {
		return err
	}
	rf, err := loadRecipients(p)
	if err != nil {
		return err
	}

	keyStr, source, defaultName, err := resolveNewKey(cmd, github, key, sshPath)
	if err != nil {
		return err
	}
	if name == "" {
		name = defaultName
	}
	if name == "" {
		return withExit(exitConfig, errors.New("a --name is required when using --key or --ssh"))
	}
	if _, err := keys.ParseRecipient(keyStr); err != nil {
		return withExit(exitConfig, err)
	}

	candidate := &keys.RecipientsFile{Recipients: append([]keys.Recipient(nil), rf.Recipients...)}
	candidate.Recipients = append(candidate.Recipients, keys.Recipient{
		Name:    name,
		Keys:    []string{keyStr},
		Source:  source,
		AddedAt: nowDate(),
		AddedBy: currentUser(),
	})
	if err := candidate.Validate(); err != nil {
		return withExit(exitConfig, err) // duplicate name or key
	}

	plaintexts := make([]string, len(cfg.Files))
	for i, fp := range cfg.Files {
		plaintexts[i] = fp.Plaintext
	}
	if err := gitint.EnsureIgnored(p.Root, plaintexts, false); err != nil {
		return withExit(exitConfig, err)
	}

	recipients, err := candidate.AgeRecipients()
	if err != nil {
		return withExit(exitConfig, err)
	}
	recipientsBytes, err := candidate.Marshal()
	if err != nil {
		return withExit(exitConfig, err)
	}
	recipientsPlan, err := crypt.PlanFile(p.Recipients, recipientsBytes, 0o644)
	if err != nil {
		return err
	}

	var identity *keys.Identity
	if flags.identity != "" || strings.TrimSpace(os.Getenv("ENVGUARDIAN_IDENTITY")) != "" {
		identity, err = keys.ResolveIdentity(flags.identity, keys.DefaultPrompter())
		if err != nil {
			return err
		}
	}
	for _, fp := range cfg.Files {
		if _, statErr := os.Stat(fp.CiphertextPath); statErr == nil {
			if identity == nil {
				identity, err = keys.ResolveIdentity(flags.identity, keys.DefaultPrompter())
				if err != nil {
					return err
				}
			}
			break
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return fmt.Errorf("inspect ciphertext %s: %w", fp.Ciphertext, statErr)
		}
	}
	ccfg := crypt.Config{
		LockPath: p.Lock, Fingerprint: candidate.Fingerprint(),
		Logf: func(f string, a ...any) { fmt.Fprintf(cmd.ErrOrStderr(), f+"\n", a...) },
	}
	if identity != nil {
		ccfg.Identities = identity.Identities
		ccfg.Label = identity.Label
	}
	plans := make([]*crypt.SealPlan, 0, len(cfg.Files))
	for _, fp := range cfg.Files {
		plan, planErr := crypt.PlanSeal(ccfg, recipients, fp.PlaintextPath, fp.CiphertextPath, fp.Ciphertext)
		if planErr != nil {
			return planErr
		}
		plans = append(plans, plan)
	}
	if err := crypt.CommitSealPlans(plans, crypt.CommitOptions{
		LockPath: p.Lock, RecipientsFingerprint: candidate.Fingerprint(),
		Additional: []*crypt.FilePlan{recipientsPlan},
	}); err != nil {
		return err
	}

	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "added recipient %q (%s)\n", name, source)
	for _, fp := range cfg.Files {
		fmt.Fprintf(out, "  re-encrypted %s → %s\n", fp.Plaintext, fp.Ciphertext)
	}
	return nil
}

// resolveNewKey turns the mutually-exclusive source flags into a key string,
// source label, and default name.
func resolveNewKey(cmd *cobra.Command, github, key, sshPath string) (keyStr, source, defaultName string, err error) {
	set := 0
	for _, v := range []string{github, key, sshPath} {
		if v != "" {
			set++
		}
	}
	if set == 0 {
		return "", "", "", withExit(exitConfig, errors.New("specify one of --github, --key, or --ssh"))
	}
	if set > 1 {
		return "", "", "", withExit(exitConfig, errors.New("--github, --key, and --ssh are mutually exclusive"))
	}

	switch {
	case github != "":
		fetched, ferr := keys.FetchGitHubKeys(cmd.Context(), github)
		if ferr != nil {
			return "", "", "", ferr
		}
		selected, selectErr := selectSingleGitHubKey(github, fetched)
		if selectErr != nil {
			return "", "", "", withExit(exitConfig, selectErr)
		}
		return selected, "github:" + github, github, nil
	case sshPath != "":
		data, rerr := os.ReadFile(sshPath) //nolint:gosec // G304: user-supplied public key path
		if rerr != nil {
			return "", "", "", fmt.Errorf("read SSH public key %s: %w", sshPath, rerr)
		}
		return strings.TrimSpace(string(data)), "manual", "", nil
	default:
		return strings.TrimSpace(key), "manual", "", nil
	}
}

func selectSingleGitHubKey(username string, fetched []string) (string, error) {
	if len(fetched) != 1 {
		return "", fmt.Errorf(
			"GitHub user %q has %d ssh-ed25519 keys; v0.1.1 requires exactly one key per recipient, so use --key/--ssh explicitly or wait for v0.2 multi-key recipient support",
			username, len(fetched))
	}
	return fetched[0], nil
}

func newListRecipientsCmd(flags *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "list-recipients",
		Short: "List who can decrypt",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runListRecipients(cmd, flags)
		},
	}
}

func runListRecipients(cmd *cobra.Command, flags *globalFlags) error {
	p, err := secureRootPaths(flags)
	if err != nil {
		return err
	}
	rf, err := loadRecipients(p)
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()

	if flags.json {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(rf.Recipients)
	}

	fmt.Fprintf(out, "%-16s %-18s %s\n", "NAME", "SOURCE", "ADDED")
	for _, r := range rf.Recipients {
		fmt.Fprintf(out, "%-16s %-18s %s\n", r.Name, r.Source, r.AddedAt)
	}
	return nil
}
