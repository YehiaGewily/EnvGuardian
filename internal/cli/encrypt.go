package cli

import (
	"errors"
	"fmt"
	"path/filepath"

	"filippo.io/age"
	"github.com/spf13/cobra"

	"github.com/YehiaGewily/envguardian/internal/crypt"
	"github.com/YehiaGewily/envguardian/internal/dotenv"
	"github.com/YehiaGewily/envguardian/internal/keys"
)

func newEncryptCmd(flags *globalFlags) *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "encrypt",
		Short: "Encrypt every plaintext file to the current recipients (idempotent)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runEncrypt(cmd, flags, force)
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "re-encrypt even when the existing ciphertext can't be verified")
	return cmd
}

func runEncrypt(cmd *cobra.Command, flags *globalFlags, force bool) error {
	p := rootPaths(flags)
	cfg, err := loadConfig(p)
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

	// Identity is best-effort: first-time and recipient-change encrypts don't
	// need it; only the decrypt-compare path does.
	var identities []age.Identity
	var label string
	if id, rerr := keys.ResolveIdentity(flags.identity, keys.DefaultPrompter()); rerr == nil {
		identities, label = id.Identities, id.Label
	}

	out := cmd.OutOrStdout()
	ccfg := crypt.Config{
		Identities:  identities,
		Label:       label,
		LockPath:    p.Lock,
		Fingerprint: rf.Fingerprint(),
		Force:       force,
		Logf:        func(f string, a ...any) { fmt.Fprintf(cmd.ErrOrStderr(), f+"\n", a...) },
	}

	for _, fp := range cfg.Files {
		plain := filepath.Join(p.Root, fp.Plaintext)
		cipher := filepath.Join(p.Root, fp.Ciphertext)
		changed, err := crypt.Seal(ccfg, recipients, plain, cipher)
		if err != nil {
			var pe *dotenv.ParseError
			if errors.As(err, &pe) {
				return withExit(exitConfig, err)
			}
			return err
		}
		if changed {
			fmt.Fprintf(out, "encrypted %s → %s\n", fp.Plaintext, fp.Ciphertext)
		} else {
			fmt.Fprintf(out, "%s → %s unchanged\n", fp.Plaintext, fp.Ciphertext)
		}
	}
	return nil
}
