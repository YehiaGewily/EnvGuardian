package cli

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/YehiaGewily/envguardian/internal/authenticity"
	"github.com/YehiaGewily/envguardian/internal/config"
	"github.com/YehiaGewily/envguardian/internal/crypt"
)

func newAddFileCmd(flags *globalFlags) *cobra.Command {
	var ciphertext string
	cmd := &cobra.Command{
		Use:   "add-file PLAINTEXT",
		Short: "Manage another plaintext file and seal it in the same transaction",
		Long: "Add a repository-relative plaintext file to config.toml and seal it. The\n" +
			"config change, the new ciphertext and signature, and the lock are written as\n" +
			"one rollback-capable transaction. The plaintext is added to .gitignore.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return exclusive(flags, func() error { return runAddFile(cmd, flags, args[0], ciphertext) })
		},
	}
	cmd.Flags().StringVar(&ciphertext, "ciphertext", "", "repository-relative ciphertext path (default: PLAINTEXT.age)")
	return cmd
}

func newRemoveFileCmd(flags *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "remove-file PLAINTEXT",
		Short: "Stop managing a plaintext file",
		Long: "Remove a mapping from config.toml and rewrite the lock in one transaction.\n" +
			"The ciphertext, its signature, and your local plaintext are left in place;\n" +
			"remove the ciphertext and signature from Git yourself.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return exclusive(flags, func() error { return runRemoveFile(cmd, flags, args[0]) })
		},
	}
}

func runAddFile(cmd *cobra.Command, flags *globalFlags, plaintext, ciphertext string) error {
	p, err := secureRootPaths(flags)
	if err != nil {
		return err
	}
	cfg, err := loadConfig(p)
	if err != nil {
		return err
	}
	plaintext = path.Clean(filepath.ToSlash(plaintext))
	if ciphertext == "" {
		ciphertext = plaintext + ".age"
	}
	ciphertext = path.Clean(filepath.ToSlash(ciphertext))
	if !strings.HasSuffix(ciphertext, ".age") {
		return withExit(exitConfig, fmt.Errorf("ciphertext path %q must end in .age so Git attributes and drivers apply to it", ciphertext))
	}
	for _, fp := range cfg.Files {
		if fp.Plaintext == plaintext {
			return withExit(exitConfig, fmt.Errorf("%s is already managed (ciphertext %s)", plaintext, fp.Ciphertext))
		}
	}
	updated := mappingsOnly(cfg)
	updated.Files = append(updated.Files, config.FilePair{Plaintext: plaintext, Ciphertext: ciphertext})
	if err := updated.ValidateAndResolve(p.Root); err != nil {
		return withExit(exitConfig, fmt.Errorf("invalid managed file mapping: %w", err))
	}
	added := updated.Files[len(updated.Files)-1]
	if _, err := os.Stat(added.PlaintextPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return withExit(exitConfig, fmt.Errorf("plaintext %s does not exist; create it first", plaintext))
		}
		return fmt.Errorf("inspect plaintext %s: %w", plaintext, err)
	}
	if _, err := os.Stat(added.CiphertextPath); err == nil {
		return withExit(exitConfig, fmt.Errorf("ciphertext %s already exists; choose another --ciphertext or remove it", ciphertext))
	}
	configPlan, err := planConfig(p, updated)
	if err != nil {
		return err
	}
	if err := sealConfiguration(cmd, flags, p, updated, false, true, []*crypt.FilePlan{configPlan}); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "now managing %s; commit %s, %s, %s, and .gitignore\n",
		plaintext, filepath.ToSlash(relOrSelf(p.Root, p.Dir)), ciphertext, authenticity.SignatureName(ciphertext))
	return nil
}

func runRemoveFile(cmd *cobra.Command, flags *globalFlags, plaintext string) error {
	p, err := secureRootPaths(flags)
	if err != nil {
		return err
	}
	cfg, err := loadConfig(p)
	if err != nil {
		return err
	}
	plaintext = path.Clean(filepath.ToSlash(plaintext))
	updated := &config.Config{Version: cfg.Version}
	var removed *config.FilePair
	for i := range cfg.Files {
		if cfg.Files[i].Plaintext == plaintext {
			removed = &cfg.Files[i]
			continue
		}
		updated.Files = append(updated.Files, config.FilePair{Plaintext: cfg.Files[i].Plaintext, Ciphertext: cfg.Files[i].Ciphertext})
	}
	if removed == nil {
		managed := make([]string, 0, len(cfg.Files))
		for _, fp := range cfg.Files {
			managed = append(managed, fp.Plaintext)
		}
		return withExit(exitConfig, fmt.Errorf("%s is not managed; managed files: %s", plaintext, strings.Join(managed, ", ")))
	}
	if len(updated.Files) == 0 {
		return withExit(exitConfig, fmt.Errorf("refusing to remove %s, the only managed file; EnvGuardian needs at least one mapping", plaintext))
	}
	if err := updated.ValidateAndResolve(p.Root); err != nil {
		return withExit(exitConfig, fmt.Errorf("invalid managed file mapping: %w", err))
	}
	configPlan, err := planConfig(p, updated)
	if err != nil {
		return err
	}
	if err := sealConfiguration(cmd, flags, p, updated, false, false, []*crypt.FilePlan{configPlan}); err != nil {
		return err
	}
	signature := authenticity.SignatureName(removed.Ciphertext)
	fmt.Fprintf(cmd.OutOrStdout(), "stopped managing %s; %s, %s, and your local %s were left in place\n", plaintext, removed.Ciphertext, signature, plaintext)
	fmt.Fprintf(cmd.OutOrStdout(), "next: git rm %s %s, then commit with %s\n", removed.Ciphertext, signature, filepath.ToSlash(relOrSelf(p.Root, p.Dir)))
	return nil
}

// mappingsOnly copies the configured mappings without resolved paths so the
// result can be validated and resolved again after an edit.
func mappingsOnly(cfg *config.Config) *config.Config {
	out := &config.Config{Version: cfg.Version, Files: make([]config.FilePair, 0, len(cfg.Files)+1)}
	for _, fp := range cfg.Files {
		out.Files = append(out.Files, config.FilePair{Plaintext: fp.Plaintext, Ciphertext: fp.Ciphertext})
	}
	return out
}

func planConfig(p config.Paths, cfg *config.Config) (*crypt.FilePlan, error) {
	data, err := cfg.Encode()
	if err != nil {
		return nil, err
	}
	return crypt.PlanFile(p.Config, data, 0o644)
}

func relOrSelf(root, target string) string {
	if rel, err := filepath.Rel(root, target); err == nil {
		return rel
	}
	return target
}
