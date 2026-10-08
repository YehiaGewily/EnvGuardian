package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/YehiaGewily/envguardian/internal/config"
	"github.com/YehiaGewily/envguardian/internal/gitint"
	"github.com/YehiaGewily/envguardian/internal/keys"
)

func newInitCmd(flags *globalFlags) *cobra.Command {
	var name, plaintext string
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Scaffold config, seed recipients with your key, and update .gitignore",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runInit(cmd, flags, name, plaintext)
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "your recipient name (default: OS username)")
	cmd.Flags().StringVar(&plaintext, "file", ".env", "plaintext file to manage")
	return cmd
}

// ciphertextAttributes stop Git from converting line endings in ciphertext and
// detached signatures. Both are verified byte-for-byte against the lock digest
// and signature, so a core.autocrlf checkout would otherwise make a teammate's
// clone fail verification.
var ciphertextAttributes = []string{"*.age -text", "*.age.sig -text"}

func runInit(cmd *cobra.Command, flags *globalFlags, name, plaintext string) error {
	p, err := secureRootPaths(flags)
	if err != nil {
		return err
	}
	// Validate --file before identity prompting or any filesystem mutation. The
	// constructed config is validated again as a whole before it is saved.
	if _, err := config.ResolveManagedPath(p.Root, plaintext); err != nil {
		return withExit(exitConfig, fmt.Errorf("invalid --file %q: %w", plaintext, err))
	}
	ciphertext := plaintext + ".age"
	if _, err := config.ResolveManagedPath(p.Root, ciphertext); err != nil {
		return withExit(exitConfig, fmt.Errorf("invalid ciphertext path derived from --file %q: %w", plaintext, err))
	}

	if _, err := os.Stat(p.Config); err == nil {
		return withExit(exitConfig, fmt.Errorf("already initialized: %s exists (refusing to overwrite)", display(p.Config)))
	}

	id, err := keys.ResolveIdentity(flags.identity, keys.DefaultPrompter())
	if err != nil {
		return err
	}
	if id.Recipient == "" {
		return withExit(exitIdentity, fmt.Errorf("could not derive a public key from the identity at %s; use an age or SSH key", id.Label))
	}
	if name == "" {
		name = currentUser()
	}
	if err := os.MkdirAll(p.Dir, 0o750); err != nil {
		return fmt.Errorf("create %s: %w", display(p.Dir), err)
	}

	cfg := &config.Config{
		Version: config.Version,
		Files:   []config.FilePair{{Plaintext: plaintext, Ciphertext: ciphertext}},
	}
	if err := cfg.ValidateAndResolve(p.Root); err != nil {
		return withExit(exitConfig, fmt.Errorf("invalid managed file mapping: %w", err))
	}
	if err := cfg.Save(p.Config); err != nil {
		return err
	}

	rf := &keys.RecipientsFile{Recipients: []keys.Recipient{{
		Name:    name,
		Keys:    []string{id.Recipient},
		Source:  "manual",
		AddedAt: nowDate(),
		AddedBy: name,
	}}}
	if err := rf.Save(p.Recipients); err != nil {
		return err
	}

	added, err := gitint.AppendIgnore(p.Root, plaintext)
	if err != nil {
		return err
	}
	if _, err := gitint.AppendIgnore(p.Root, config.AutoDecryptStateRelative); err != nil {
		return err
	}
	attributesAdded := false
	for _, line := range ciphertextAttributes {
		lineAdded, err := gitint.AppendLine(filepath.Join(p.Root, ".gitattributes"), line)
		if err != nil {
			return err
		}
		attributesAdded = attributesAdded || lineAdded
	}

	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "initialized envguardian in %s\n", display(p.Dir))
	fmt.Fprintf(out, "  config:     %s\n", display(p.Config))
	fmt.Fprintf(out, "  recipients: %s (seeded with %q)\n", display(p.Recipients), name)
	if added {
		fmt.Fprintf(out, "  gitignore:  added %s\n", plaintext)
	} else {
		fmt.Fprintf(out, "  gitignore:  %s already ignored\n", plaintext)
	}
	if attributesAdded {
		fmt.Fprintln(out, "  attributes: .gitattributes keeps *.age and *.age.sig byte-exact (-text)")
	} else {
		fmt.Fprintln(out, "  attributes: .gitattributes already keeps ciphertext byte-exact")
	}
	fmt.Fprintf(out, "next: create %s, then run `envguardian encrypt`\n", plaintext)
	return nil
}
