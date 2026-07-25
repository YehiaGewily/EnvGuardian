package cli

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/YehiaGewily/envguardian/internal/crypt"
	"github.com/YehiaGewily/envguardian/internal/keys"
)

func newDecryptCmd(flags *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "decrypt",
		Short: "Decrypt every ciphertext file to its plaintext (mode 0600)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runDecrypt(cmd, flags)
		},
	}
}

func runDecrypt(cmd *cobra.Command, flags *globalFlags) error {
	p := rootPaths(flags)
	cfg, err := loadConfig(p)
	if err != nil {
		return err
	}

	id, err := keys.ResolveIdentity(flags.identity, keys.DefaultPrompter())
	if err != nil {
		return err // *NoIdentityError → exit 2
	}

	ccfg := crypt.Config{Identities: id.Identities, Label: id.Label}
	out := cmd.OutOrStdout()
	for _, fp := range cfg.Files {
		plain := filepath.Join(p.Root, fp.Plaintext)
		cipher := filepath.Join(p.Root, fp.Ciphertext)
		if err := crypt.Open(ccfg, cipher, plain); err != nil {
			return err // ErrNotARecipient → exit 2
		}
		fmt.Fprintf(out, "decrypted %s → %s\n", fp.Ciphertext, fp.Plaintext)
	}
	return nil
}
