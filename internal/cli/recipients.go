package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/YehiaGewily/envguardian/internal/crypt"
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
	p := rootPaths(flags)
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

	rf.Recipients = append(rf.Recipients, keys.Recipient{
		Name:    name,
		Key:     keyStr,
		Source:  source,
		AddedAt: nowDate(),
		AddedBy: currentUser(),
	})
	if err := rf.Validate(); err != nil {
		return withExit(exitConfig, err) // duplicate name or key
	}
	if err := rf.Save(p.Recipients); err != nil {
		return err
	}

	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "added recipient %q (%s)\n", name, source)

	// The recipient set changed, so the fingerprint changes and Seal re-encrypts
	// unconditionally — no identity needed.
	recipients, err := rf.AgeRecipients()
	if err != nil {
		return withExit(exitConfig, err)
	}
	ccfg := crypt.Config{
		LockPath:    p.Lock,
		Fingerprint: rf.Fingerprint(),
		Logf:        func(f string, a ...any) { fmt.Fprintf(cmd.ErrOrStderr(), f+"\n", a...) },
	}
	for _, fp := range cfg.Files {
		plain := filepath.Join(p.Root, fp.Plaintext)
		cipher := filepath.Join(p.Root, fp.Ciphertext)
		if _, err := os.Stat(plain); err != nil {
			fmt.Fprintf(out, "  skipped %s (no local plaintext; run decrypt then encrypt)\n", fp.Plaintext)
			continue
		}
		if _, err := crypt.Seal(ccfg, recipients, plain, cipher); err != nil {
			return err
		}
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
		return fetched[0], "github:" + github, github, nil
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
	p := rootPaths(flags)
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
