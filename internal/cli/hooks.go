package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"github.com/spf13/cobra"

	"github.com/YehiaGewily/envguardian/internal/config"
	"github.com/YehiaGewily/envguardian/internal/crypt"
	"github.com/YehiaGewily/envguardian/internal/gitint"
	"github.com/YehiaGewily/envguardian/internal/keys"
)

const (
	hookBegin = "# >>> envguardian managed block >>>"
	hookEnd   = "# <<< envguardian managed block <<<"
)

// managedHooks are the hook names we install, in a stable order.
var managedHooks = []string{"post-merge", "post-checkout", "pre-commit"}

func newInstallHooksCmd(flags *globalFlags) *cobra.Command {
	var uninstall bool
	cmd := &cobra.Command{
		Use:   "install-hooks",
		Short: "Install git hooks: auto-decrypt after pull, block plaintext commits",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runInstallHooks(cmd, flags, uninstall)
		},
	}
	cmd.Flags().BoolVar(&uninstall, "uninstall", false, "remove EnvGuardian's hook blocks")
	return cmd
}

func runInstallHooks(cmd *cobra.Command, flags *globalFlags, uninstall bool) error {
	root := gitRoot(rootPaths(flags).Root)
	dir, err := hooksDir(root)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create hooks dir %s: %w", display(dir), err)
	}

	exe := selfPath()
	out := cmd.OutOrStdout()

	if uninstall {
		for _, name := range managedHooks {
			removed, err := uninstallHook(filepath.Join(dir, name))
			if err != nil {
				return err
			}
			if removed {
				fmt.Fprintf(out, "removed %s block from %s\n", "envguardian", display(filepath.Join(dir, name)))
			}
		}
		return nil
	}
	if _, err := gitint.AppendIgnore(root, config.AutoDecryptStateRelative); err != nil {
		return fmt.Errorf("gitignore automatic-decryption state: %w", err)
	}

	for _, name := range managedHooks {
		if err := installHook(filepath.Join(dir, name), hookBody(name, exe)); err != nil {
			return err
		}
		fmt.Fprintf(out, "installed %s hook\n", name)
	}
	fmt.Fprintf(out, "hooks written to %s\n", display(dir))
	fmt.Fprintln(out, "next: review the current commit, then run `envguardian decrypt --accept-changes` once to establish automatic-decryption trust")
	return nil
}

// hookBody returns the shell lines (between markers) for a hook. Portable
// /bin/sh, no bashisms.
func hookBody(name, exe string) string {
	switch name {
	case "post-checkout":
		// Only decrypt on a full branch checkout ($3 == 1), not file checkouts.
		return fmt.Sprintf("[ \"$3\" = \"1\" ] || exit 0\n%q hook-auto-decrypt", exe)
	case "post-merge":
		return fmt.Sprintf("%q hook-auto-decrypt", exe)
	case "pre-commit":
		return fmt.Sprintf("%q hook-pre-commit || exit 1", exe)
	default:
		return ""
	}
}

// installHook writes or updates the managed block in a hook file idempotently,
// preserving any existing (non-managed) content.
func installHook(path, body string) error {
	block := hookBegin + "\n" + body + "\n" + hookEnd + "\n"

	existing, err := os.ReadFile(path) //nolint:gosec // G304: git hook path under the repo
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("read hook %s: %w", path, err)
		}
		content := "#!/bin/sh\n" + block
		return writeExecutable(path, content)
	}

	content := spliceBlock(string(existing), block)
	// A pre-existing hook may lack a shebang if it was hand-written oddly; leave
	// it as-is (we only own our block).
	return writeExecutable(path, content)
}

// spliceBlock replaces an existing managed block, or appends one if absent.
func spliceBlock(content, block string) string {
	bi := strings.Index(content, hookBegin)
	if bi < 0 {
		if content != "" && !strings.HasSuffix(content, "\n") {
			content += "\n"
		}
		return content + block
	}
	rest := content[bi:]
	ee := strings.Index(rest, hookEnd)
	if ee < 0 {
		head := content[:bi]
		if head != "" && !strings.HasSuffix(head, "\n") {
			head += "\n"
		}
		return head + block
	}
	endPos := bi + ee + len(hookEnd)
	tail := strings.TrimPrefix(content[endPos:], "\n")
	return content[:bi] + block + tail
}

// uninstallHook removes only our block. If nothing meaningful remains, it
// removes the file.
func uninstallHook(path string) (bool, error) {
	existing, err := os.ReadFile(path) //nolint:gosec // G304: git hook path under the repo
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("read hook %s: %w", path, err)
	}
	content := string(existing)
	bi := strings.Index(content, hookBegin)
	if bi < 0 {
		return false, nil
	}
	rest := content[bi:]
	ee := strings.Index(rest, hookEnd)
	if ee < 0 {
		return false, nil
	}
	endPos := bi + ee + len(hookEnd)
	stripped := content[:bi] + strings.TrimPrefix(content[endPos:], "\n")

	if t := strings.TrimSpace(stripped); t == "" || t == "#!/bin/sh" {
		if err := os.Remove(path); err != nil {
			return false, fmt.Errorf("remove hook %s: %w", path, err)
		}
		return true, nil
	}
	if err := writeExecutable(path, stripped); err != nil {
		return false, err
	}
	return true, nil
}

func writeExecutable(path, content string) error {
	if err := os.WriteFile(path, []byte(content), 0o750); err != nil { //nolint:gosec // hook must be executable
		return fmt.Errorf("write hook %s: %w", path, err)
	}
	return nil
}

// hooksDir resolves the hooks directory, honoring core.hooksPath.
func hooksDir(root string) (string, error) {
	if hp := gitConfigValue(root, "core.hooksPath"); hp != "" {
		if !filepath.IsAbs(hp) {
			hp = filepath.Join(root, hp)
		}
		return hp, nil
	}
	if out := gitOutput(root, "rev-parse", "--git-path", "hooks"); out != "" {
		if !filepath.IsAbs(out) {
			out = filepath.Join(root, out)
		}
		return out, nil
	}
	return filepath.Join(root, ".git", "hooks"), nil
}

// gitRoot returns the repo top level, falling back to the given root.
func gitRoot(fallback string) string {
	if out := gitOutput(fallback, "rev-parse", "--show-toplevel"); out != "" {
		return out
	}
	return fallback
}

func gitConfigValue(dir, key string) string {
	return gitOutput(dir, "config", "--get", key)
}

func gitOutput(dir string, args ...string) string {
	cmd := exec.Command("git", args...) // #nosec G204 -- fixed binary, literal args
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// gitRun runs a git command and returns an error with git's output on failure.
func gitRun(dir string, args ...string) error {
	cmd := exec.Command("git", args...) // #nosec G204 -- fixed binary, literal args
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// selfPath returns this binary's path with forward slashes (so it works from
// /bin/sh on Windows too), falling back to the bare command name.
func selfPath() string {
	exe, err := os.Executable()
	if err != nil {
		return "envguardian"
	}
	return filepath.ToSlash(exe)
}

// newHookPreCommitCmd is the hidden command the pre-commit hook invokes.
func newHookPreCommitCmd(flags *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:    "hook-pre-commit",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runHookPreCommit(flags)
		},
	}
}

func runHookPreCommit(flags *globalFlags) error {
	p := rootPaths(flags)
	cfg, err := config.Load(p.Root, p.Config)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // not an EnvGuardian repo; don't interfere
		}
		return withExit(exitConfig, err)
	}

	root := gitRoot(p.Root)
	staged := stagedFiles(root)

	// 1. Block any staged plaintext env file.
	var leaking []string
	for _, fp := range cfg.Files {
		if staged[filepath.ToSlash(fp.Plaintext)] {
			leaking = append(leaking, fp.Plaintext)
		}
	}
	if len(leaking) > 0 {
		return withExit(exitConfig, fmt.Errorf(
			"refusing to commit plaintext secret file(s): %s\n  these are encrypted into their .age counterparts; never commit the plaintext.\n  fix: `git rm --cached %s` and commit the .age file instead",
			strings.Join(leaking, ", "), strings.Join(leaking, " ")))
	}

	// 2. Fail if any ciphertext is out of date relative to the plaintext.
	var ageIDs []age.Identity
	if id, rerr := keys.ResolveIdentity(flags.identity, keys.DefaultPrompter()); rerr == nil {
		ageIDs = id.Identities
	}
	for _, fp := range cfg.Files {
		st, err := crypt.Inspect(ageIDs, fp.CiphertextPath, fp.PlaintextPath)
		if err != nil {
			return withExit(exitConfig, err)
		}
		if st.Decryptable && st.PlaintextExists && !st.Matches {
			return withExit(exitOutOfSync, fmt.Errorf(
				"%s is out of date: %s changed but was not re-encrypted; run `envguardian encrypt` before committing",
				fp.Ciphertext, fp.Plaintext))
		}
	}
	return nil
}

// stagedFiles returns the set of paths staged in the index (forward-slashed).
func stagedFiles(root string) map[string]bool {
	set := map[string]bool{}
	out := gitOutput(root, "diff", "--cached", "--name-only")
	for _, line := range strings.Split(out, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			set[filepath.ToSlash(line)] = true
		}
	}
	return set
}
