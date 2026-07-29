package cli

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/YehiaGewily/envguardian/internal/crypt"
	"github.com/YehiaGewily/envguardian/internal/gitint"
	"github.com/YehiaGewily/envguardian/internal/keys"
)

func newEncryptCmd(flags *globalFlags) *cobra.Command {
	var force, fix bool
	cmd := &cobra.Command{
		Use:   "encrypt",
		Short: "Encrypt every plaintext file to the current recipients (idempotent)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runEncrypt(cmd, flags, force, fix)
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "re-encrypt even when the existing ciphertext can't be verified")
	cmd.Flags().BoolVar(&fix, "fix", false, "append any unignored plaintext files to .gitignore")
	return cmd
}

func runEncrypt(cmd *cobra.Command, flags *globalFlags, force, fix bool) error {
	p, err := secureRootPaths(flags)
	if err != nil {
		return err
	}
	cfg, err := loadConfig(p)
	if err != nil {
		return err
	}

	// Refuse to encrypt a plaintext file git isn't ignoring — committing it
	// would leak the secret into history.
	plaintexts := make([]string, len(cfg.Files))
	for i, fp := range cfg.Files {
		plaintexts[i] = fp.Plaintext
	}
	if err := gitint.EnsureIgnored(p.Root, plaintexts, fix); err != nil {
		var ni *gitint.NotIgnoredError
		if errors.As(err, &ni) {
			return withExit(exitConfig, err)
		}
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

	// Stage D requires an SSH identity for every new or replacement signature.
	// Existing ciphertext also uses its age-compatible form for decrypt-compare.
	id, err := keys.ResolveIdentity(flags.identity, keys.DefaultPrompter())
	if err != nil {
		return err
	}

	out := cmd.OutOrStdout()
	ccfg := crypt.Config{
		Identities:  id.Identities,
		Label:       id.Label,
		LockPath:    p.Lock,
		Fingerprint: rf.Fingerprint(),
		Force:       force,
		Logf:        func(f string, a ...any) { fmt.Fprintf(cmd.ErrOrStderr(), f+"\n", a...) },
	}

	plans := make([]*crypt.SealPlan, 0, len(cfg.Files))
	for _, fp := range cfg.Files {
		plan, err := crypt.PlanSeal(ccfg, recipients, fp.PlaintextPath, fp.CiphertextPath, fp.Ciphertext)
		if err != nil {
			return err
		}
		plans = append(plans, plan)
	}
	signaturePlans := make([]*crypt.FilePlan, 0, len(cfg.Files))
	for i, fp := range cfg.Files {
		signaturePlan, signErr := planCiphertextSignature(p, fp, rf.Fingerprint(), rf, id, plans[i])
		if signErr != nil {
			return signErr
		}
		signaturePlans = append(signaturePlans, signaturePlan)
	}
	if err := crypt.CommitSealPlans(plans, crypt.CommitOptions{
		LockPath: p.Lock, RecipientsFingerprint: rf.Fingerprint(), Additional: signaturePlans,
	}); err != nil {
		return err
	}
	for i, fp := range cfg.Files {
		if plans[i].Changed {
			fmt.Fprintf(out, "encrypted %s → %s\n", fp.Plaintext, fp.Ciphertext)
		} else {
			fmt.Fprintf(out, "%s → %s unchanged\n", fp.Plaintext, fp.Ciphertext)
		}
	}
	return nil
}
