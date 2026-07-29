package cli

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/YehiaGewily/envguardian/internal/crypt"
	"github.com/YehiaGewily/envguardian/internal/dotenv"
	"github.com/YehiaGewily/envguardian/internal/gitint"
	"github.com/YehiaGewily/envguardian/internal/keys"
)

func newDiffCmd(flags *globalFlags) *cobra.Command {
	var install bool
	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Show which keys changed (names only, never values)",
		Long:  "Compare working plaintext with ciphertext and emit only added, removed, or changed key names. Values and plaintext derivatives are never emitted.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if install {
				return installDiffDriver(cmd, flags)
			}
			return workingDiff(cmd, flags)
		},
	}
	cmd.Flags().BoolVar(&install, "install", false, "register the git diff driver (.gitattributes + git config)")
	return cmd
}

func newDiffDriverCmd(flags *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:    "diff-driver PATH OLD OLD_HEX OLD_MODE NEW NEW_HEX NEW_MODE",
		Hidden: true,
		Args:   cobra.ExactArgs(7),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDiffDriver(cmd, flags, args)
		},
	}
}

// runDiffDriver is Git's external-diff entry point. Unlike textconv, it sees
// both sides and can therefore report value-only changes without emitting any
// value, length, hash, or prefix.
func runDiffDriver(cmd *cobra.Command, flags *globalFlags, args []string) error {
	id, err := keys.ResolveIdentity(flags.identity, keys.DefaultPrompter())
	if err != nil {
		return err
	}
	oldData, err := os.ReadFile(args[1]) //nolint:gosec // temp path supplied by Git's external diff protocol
	if err != nil {
		return fmt.Errorf("read old ciphertext for %s: %w", args[0], err)
	}
	newData, err := os.ReadFile(args[4]) //nolint:gosec // temp path supplied by Git's external diff protocol
	if err != nil {
		return fmt.Errorf("read new ciphertext for %s: %w", args[0], err)
	}
	_, oldFile, err := crypt.DecryptBytesToDotenv(id.Identities, oldData)
	if err != nil {
		return fmt.Errorf("decrypt old side of %s: %w", args[0], err)
	}
	_, newFile, err := crypt.DecryptBytesToDotenv(id.Identities, newData)
	if err != nil {
		return fmt.Errorf("decrypt new side of %s: %w", args[0], err)
	}
	added, removed, changed := diffKeys(oldFile, newFile)
	out := cmd.OutOrStdout()
	for _, key := range added {
		fmt.Fprintf(out, "+ %s\n", key)
	}
	for _, key := range removed {
		fmt.Fprintf(out, "- %s\n", key)
	}
	for _, key := range changed {
		fmt.Fprintf(out, "~ %s\n", key)
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

	command := shellQuote(selfPath()) + " diff-driver"
	if err := gitRun(root, "config", "--local", "diff.envguardian.command", command); err != nil {
		return err
	}
	// Remove the obsolete one-sided driver if an earlier development build
	// installed it. A missing value is the expected clean state.
	unset := exec.Command("git", "config", "--local", "--unset-all", "diff.envguardian.textconv") // #nosec G204 -- fixed command
	unset.Dir = root
	if out, unsetErr := unset.CombinedOutput(); unsetErr != nil {
		if exitErr, ok := unsetErr.(*exec.ExitError); !ok || exitErr.ExitCode() != 5 {
			return fmt.Errorf("remove obsolete diff textconv setting: %w: %s", unsetErr, strings.TrimSpace(string(out)))
		}
	}

	out := cmd.OutOrStdout()
	if added {
		fmt.Fprintln(out, "added `*.age diff=envguardian` to .gitattributes")
	} else {
		fmt.Fprintln(out, ".gitattributes already has the diff attribute")
	}
	fmt.Fprintln(out, "configured local git diff.envguardian.command")
	fmt.Fprintln(out, "commit .gitattributes so teammates get readable `git diff` on .age files")
	return nil
}

// shellQuote returns one POSIX-shell word. Git executes external diff command
// strings through a shell even on Windows, so quotes, dollars, and backticks in
// the executable path must stay literal.
func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
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
