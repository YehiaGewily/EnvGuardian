package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/YehiaGewily/envguardian/internal/crypt"
	"github.com/YehiaGewily/envguardian/internal/gitint"
	"github.com/YehiaGewily/envguardian/internal/keys"
	"github.com/YehiaGewily/envguardian/internal/rotation"
)

const historyWarning = "re-encryption removes access only from new ciphertext; it cannot revoke secrets already present in git history"

func newRevokeCmd(flags *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "revoke NAME",
		Short: "Revoke a recipient and record every exposed key for rotation",
		Long: "Remove a recipient through the transactional seal planner and add each dotenv key\n" +
			"they could read to the rotation ledger. " + historyWarning + ".",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRevoke(cmd, flags, args[0])
		},
	}
}

func runRevoke(cmd *cobra.Command, flags *globalFlags, name string) error {
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
	if len(rf.Recipients) == 1 {
		return withExit(exitConfig, errors.New("refusing to revoke the last recipient; add a replacement recipient first"))
	}

	index := -1
	for i, recipient := range rf.Recipients {
		if recipient.Name == name {
			index = i
			break
		}
	}
	if index < 0 {
		return withExit(exitConfig, fmt.Errorf("recipient %q does not exist", name))
	}
	candidate := &keys.RecipientsFile{Recipients: append([]keys.Recipient(nil), rf.Recipients...)}
	candidate.Recipients = append(candidate.Recipients[:index], candidate.Recipients[index+1:]...)
	if err := candidate.Validate(); err != nil {
		return withExit(exitConfig, err)
	}

	plaintexts := make([]string, len(cfg.Files))
	for i, fp := range cfg.Files {
		plaintexts[i] = fp.Plaintext
	}
	if err := gitint.EnsureIgnored(p.Root, plaintexts, false); err != nil {
		return withExit(exitConfig, err)
	}

	identity, err := keys.ResolveIdentity(flags.identity, keys.DefaultPrompter())
	if err != nil {
		return err
	}
	recipients, err := candidate.AgeRecipients()
	if err != nil {
		return withExit(exitConfig, err)
	}
	ledger, err := rotation.Load(p.Rotation)
	if err != nil {
		return withExit(exitConfig, err)
	}

	var exposedKeys []string
	for _, fp := range cfg.Files {
		ciphertext, readErr := os.ReadFile(fp.CiphertextPath) //nolint:gosec // validated managed ciphertext path
		if errors.Is(readErr, os.ErrNotExist) {
			continue
		}
		if readErr != nil {
			return fmt.Errorf("read ciphertext %s before revocation: %w", fp.Ciphertext, readErr)
		}
		_, _, verifyErr := verifyCiphertextSignature(p, fp, rf, ciphertext)
		if verifyErr != nil {
			return verifyErr
		}
		_, file, decryptErr := crypt.DecryptBytesToDotenv(identity.Identities, ciphertext)
		if decryptErr != nil {
			return fmt.Errorf("decrypt %s before revocation: %w", fp.Ciphertext, decryptErr)
		}
		exposedKeys = append(exposedKeys, file.Keys()...)
	}
	if err := ledger.AddKeys(exposedKeys); err != nil {
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
	ledgerBytes, err := ledger.Marshal()
	if err != nil {
		return withExit(exitConfig, err)
	}
	ledgerPlan, err := crypt.PlanFile(p.Rotation, ledgerBytes, 0o644)
	if err != nil {
		return err
	}

	ccfg := crypt.Config{
		Identities: identity.Identities, Label: identity.Label, LockPath: p.Lock,
		Fingerprint: candidate.Fingerprint(),
		Logf:        func(format string, args ...any) { fmt.Fprintf(cmd.ErrOrStderr(), format+"\n", args...) },
	}
	plans := make([]*crypt.SealPlan, 0, len(cfg.Files))
	for _, fp := range cfg.Files {
		plan, planErr := crypt.PlanSeal(ccfg, recipients, fp.PlaintextPath, fp.CiphertextPath, fp.Ciphertext)
		if planErr != nil {
			return planErr
		}
		plans = append(plans, plan)
	}
	additional := []*crypt.FilePlan{recipientsPlan, ledgerPlan}
	for i, fp := range cfg.Files {
		signaturePlan, signErr := planCiphertextSignature(p, fp, candidate.Fingerprint(), candidate, identity, plans[i])
		if signErr != nil {
			return signErr
		}
		additional = append(additional, signaturePlan)
	}
	if err := crypt.CommitSealPlans(plans, crypt.CommitOptions{
		LockPath: p.Lock, RecipientsFingerprint: candidate.Fingerprint(), Additional: additional,
	}); err != nil {
		return err
	}

	fmt.Fprintf(cmd.OutOrStdout(), "revoked recipient %q and re-encrypted %d ciphertext(s)\n", name, len(cfg.Files))
	fmt.Fprintf(cmd.OutOrStdout(), "WARNING: %s. Rotate the pending key names and then mark each one done.\n", historyWarning)
	return nil
}

func newRotationCmd(flags *globalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rotation",
		Short: "Track key names that must be rotated after revocation",
		Long:  "Track key names that must be rotated after revocation. " + historyWarning + ".",
		Args:  cobra.NoArgs,
	}
	cmd.AddCommand(newRotationStatusCmd(flags), newRotationDoneCmd(flags))
	return cmd
}

func newRotationStatusCmd(flags *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "List pending rotation key names",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			p, err := secureRootPaths(flags)
			if err != nil {
				return err
			}
			ledger, err := rotation.Load(p.Rotation)
			if err != nil {
				return withExit(exitConfig, err)
			}
			return printRotationStatus(cmd, flags, ledger.Keys())
		},
	}
}

func newRotationDoneCmd(flags *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "done KEY",
		Short: "Mark one rotated key name complete",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := secureRootPaths(flags)
			if err != nil {
				return err
			}
			ledger, err := rotation.Load(p.Rotation)
			if err != nil {
				return withExit(exitConfig, err)
			}
			key := strings.TrimSpace(args[0])
			if !ledger.Done(key) {
				return withExit(exitOutOfSync, fmt.Errorf("key %q is not pending rotation", key))
			}
			if err := ledger.Save(p.Rotation); err != nil {
				return err
			}
			if flags.json {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(struct {
					Done    string   `json:"done"`
					Pending []string `json:"pending"`
				}{Done: key, Pending: ledger.Keys()})
			}
			fmt.Fprintf(cmd.OutOrStdout(), "marked %s rotated\n", key)
			return nil
		},
	}
}

func printRotationStatus(cmd *cobra.Command, flags *globalFlags, keys []string) error {
	sort.Strings(keys)
	if flags.json {
		return json.NewEncoder(cmd.OutOrStdout()).Encode(struct {
			Pending []string `json:"pending"`
		}{Pending: keys})
	}
	if len(keys) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "no key names are pending rotation")
		return nil
	}
	fmt.Fprintln(cmd.OutOrStdout(), "pending rotation key names:")
	for _, key := range keys {
		fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", key)
	}
	return nil
}
