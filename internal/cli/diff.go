package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/spf13/cobra"

	"github.com/YehiaGewily/envguardian/internal/crypt"
	"github.com/YehiaGewily/envguardian/internal/dotenv"
	"github.com/YehiaGewily/envguardian/internal/gitint"
	"github.com/YehiaGewily/envguardian/internal/keys"
)

func newDiffCmd(flags *globalFlags) *cobra.Command {
	var install bool
	cmd := &cobra.Command{
		Use:   "diff [ciphertext-file]",
		Short: "Show which keys changed (names only, never values)",
		Long: "With no argument, diffs each working plaintext against its committed\n" +
			"ciphertext. With a file argument it acts as a git textconv driver,\n" +
			"emitting the decrypted key names (only) so `git diff` on .age files is\n" +
			"readable. Values, lengths, and hashes are never emitted.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch {
			case install:
				return installDiffDriver(cmd, flags)
			case len(args) == 1:
				return textconvDiff(cmd, flags, args[0])
			default:
				return workingDiff(cmd, flags)
			}
		},
	}
	cmd.Flags().BoolVar(&install, "install", false, "register the git diff driver (.gitattributes + git config)")
	return cmd
}

// textconvDiff is the git textconv entry point: emit the sorted key NAMES of the
// decrypted file, one per line. Never values — this output can reach CI logs.
func textconvDiff(cmd *cobra.Command, flags *globalFlags, file string) error {
	id, err := keys.ResolveIdentity(flags.identity, keys.DefaultPrompter())
	if err != nil {
		return err
	}
	f, err := crypt.DecryptToDotenv(id.Identities, file)
	if err != nil {
		// Not a recipient / unreadable: fail so git falls back to a binary diff
		// notice rather than showing a misleading empty diff.
		return fmt.Errorf("cannot decrypt %s for diff: %w", file, err)
	}
	keyNames := append([]string(nil), f.Keys()...)
	sort.Strings(keyNames)
	out := cmd.OutOrStdout()
	for _, k := range keyNames {
		fmt.Fprintln(out, k)
	}
	return nil
}

// workingDiff compares each working plaintext against its committed ciphertext
// and prints added/removed/changed key names.
func workingDiff(cmd *cobra.Command, flags *globalFlags) error {
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
		return err
	}

	out := cmd.OutOrStdout()
	for _, fp := range cfg.Files {
		old, err := crypt.DecryptToDotenv(id.Identities, fp.CiphertextPath)
		if err != nil {
			return fmt.Errorf("decrypt %s: %w", fp.Ciphertext, err)
		}
		newF, err := parsePlaintext(fp.PlaintextPath)
		if err != nil {
			return withExit(exitConfig, err)
		}
		added, removed, changed := diffKeys(old, newF)
		if len(added)+len(removed)+len(changed) == 0 {
			fmt.Fprintf(out, "%s: no key changes\n", fp.Plaintext)
			continue
		}
		fmt.Fprintf(out, "%s:\n", fp.Plaintext)
		for _, k := range added {
			fmt.Fprintf(out, "  + %s\n", k)
		}
		for _, k := range removed {
			fmt.Fprintf(out, "  - %s\n", k)
		}
		for _, k := range changed {
			fmt.Fprintf(out, "  ~ %s\n", k)
		}
	}
	return nil
}

// diffKeys compares two dotenv files by key/value set, returning sorted names.
// Values are read for the change check but never returned or emitted.
func diffKeys(old, newF *dotenv.File) (added, removed, changed []string) {
	oldKeys := map[string]bool{}
	for _, k := range old.Keys() {
		oldKeys[k] = true
	}
	newKeys := map[string]bool{}
	for _, k := range newF.Keys() {
		newKeys[k] = true
	}
	for _, k := range newF.Keys() {
		if !oldKeys[k] {
			added = append(added, k)
			continue
		}
		ov, _ := old.Get(k)
		nv, _ := newF.Get(k)
		if ov != nv {
			changed = append(changed, k)
		}
	}
	for _, k := range old.Keys() {
		if !newKeys[k] {
			removed = append(removed, k)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	sort.Strings(changed)
	return added, removed, changed
}

func installDiffDriver(cmd *cobra.Command, flags *globalFlags) error {
	p, err := secureRootPaths(flags)
	if err != nil {
		return err
	}
	root := gitRoot(p.Root)

	added, err := gitint.AppendLine(filepath.Join(root, ".gitattributes"), "*.age diff=envguardian")
	if err != nil {
		return err
	}

	textconv := fmt.Sprintf("%q diff", selfPath())
	if err := gitRun(root, "config", "diff.envguardian.textconv", textconv); err != nil {
		return err
	}

	out := cmd.OutOrStdout()
	if added {
		fmt.Fprintln(out, "added `*.age diff=envguardian` to .gitattributes")
	} else {
		fmt.Fprintln(out, ".gitattributes already has the diff attribute")
	}
	fmt.Fprintln(out, "configured git diff.envguardian.textconv")
	fmt.Fprintln(out, "commit .gitattributes so teammates get readable `git diff` on .age files")
	return nil
}

// parsePlaintext reads and parses a plaintext env file.
func parsePlaintext(path string) (*dotenv.File, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: user-configured plaintext path
	if err != nil {
		return nil, fmt.Errorf("read plaintext %s: %w", path, err)
	}
	f, err := dotenv.Parse(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("plaintext %s is not valid dotenv; refusing to diff", path)
	}
	return f, nil
}
