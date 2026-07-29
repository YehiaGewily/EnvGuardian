package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/YehiaGewily/envguardian/internal/crypt"
	"github.com/YehiaGewily/envguardian/internal/keys"
)

func newDecryptCmd(flags *globalFlags) *cobra.Command {
	var acceptChanges bool
	cmd := &cobra.Command{
		Use:   "decrypt",
		Short: "Decrypt every ciphertext file to its plaintext (mode 0600)",
		Args:  cobra.NoArgs,
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
		signer, missing, verifyErr := verifyCiphertextSignature(p, fp, rf, ciphertext)
		if verifyErr != nil {
			return verifyErr
		}
		if missing {
			fmt.Fprintf(cmd.ErrOrStderr(), "%s: %s\n", unsignedMigrationWarning, fp.Ciphertext)
		} else if flags.verbose {
			fmt.Fprintf(cmd.ErrOrStderr(), "envguardian: verbose: signature for %s verified as recipient %q\n", fp.Ciphertext, signer)
		}
		if err := crypt.Open(ccfg, fp.CiphertextPath, fp.PlaintextPath); err != nil {
			return err // ErrNotARecipient → exit 2
		}
		fmt.Fprintf(out, "decrypted %s → %s\n", fp.Ciphertext, fp.Plaintext)
	}
	return nil
}
