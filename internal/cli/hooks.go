package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

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
	p, err := secureRootPaths(flags)
	if err != nil {
		return err
	}
	root := gitRoot(p.Root)
	dir, err := hooksDir(root)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create hooks dir %s: %w", display(dir), err)
	}

	exe := selfPath()
	configPath := ""
	if flags.config != "" {
		configPath = filepath.ToSlash(p.Config)
	}
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
		if err := installHook(filepath.Join(dir, name), hookBody(name, exe, configPath)); err != nil {
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

func hookBody(name, exe, configPath string) string {
	invoke := func(subcommand string) string {
		if configPath != "" {
			return fmt.Sprintf("%q --config %q %s", exe, configPath, subcommand)
		}
		return fmt.Sprintf("%q %s", exe, subcommand)
	}
	switch name {
	case "post-checkout":
		// Only decrypt on a full branch checkout ($3 == 1), not file checkouts.
		return "[ \"$3\" = \"1\" ] || exit 0\n" + invoke("hook-auto-decrypt")
	case "post-merge":
		return invoke("hook-auto-decrypt")
	case "pre-commit":
		return invoke("hook-pre-commit") + " || exit 1"
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
	if !validShellShebang(string(existing)) {
		return fmt.Errorf("refusing to modify hook %s because it has no supported shell shebang; use #!/bin/sh (or a compatible sh/bash shebang) or remove the malformed hook", path)
	}

	content := spliceBlock(string(existing), block)
	return writeExecutable(path, content)
}

func validShellShebang(content string) bool {
	first, _, _ := strings.Cut(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
	first = strings.TrimSpace(first)
	return first == "#!/bin/sh" || first == "#!/bin/bash" || first == "#!/usr/bin/env sh" || first == "#!/usr/bin/env bash"
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
		if errors.Is(err, os.ErrNotExist) {
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

// gitBytes runs git without trimming its output. Callers that parse filenames
// use -z and split on NUL, so whitespace and unusual path characters survive.
func gitBytes(dir string, args ...string) ([]byte, error) {
	cmd := exec.Command("git", args...) // #nosec G204 -- fixed binary, literal args
	cmd.Dir = dir
	out, err := cmd.Output()
	if err == nil {
		return out, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return nil, fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(exitErr.Stderr)))
	}
	return nil, fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
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
	p, err := secureRootPaths(flags)
	if err != nil {
		return err
	}
	rootBytes, err := gitBytes(p.Root, "rev-parse", "--show-toplevel")
	if err != nil {
		return withExit(exitConfig, fmt.Errorf("pre-commit requires a readable Git repository: %w", err))
	}
	root := strings.TrimSpace(string(rootBytes))
	configRel, err := repoRelative(root, p.Config)
	if err != nil {
		return withExit(exitConfig, err)
	}
	configRel = filepath.ToSlash(configRel)

	staged, err := stagedFiles(root)
	if err != nil {
		return withExit(exitConfig, err)
	}
	configData, configPresent, err := indexBlob(root, configRel)
	if err != nil {
		return withExit(exitConfig, err)
	}
	if !configPresent {
		// A removed config disables EnvGuardian in the incoming snapshot. Still
		// use the previous snapshot, when available, to block smuggling its
		// managed plaintext into the same commit.
		if staged[configRel] {
			if oldData, present, oldErr := headBlob(root, configRel); oldErr != nil {
				return withExit(exitConfig, oldErr)
			} else if present {
				oldCfg, parseErr := config.Parse(root, oldData)
				if parseErr != nil {
					return withExit(exitConfig, fmt.Errorf("parse previous config while removing it: %w", parseErr))
				}
				if err := rejectStagedPlaintext(root, oldCfg); err != nil {
					return err
				}
			}
		} else if workingCfg, loadErr := config.Load(root, p.Config); loadErr == nil {
			// The first commit may stage a plaintext before staging EnvGuardian's
			// new config. Use the working config only as a conservative leak guard;
			// no trust or integrity decision is derived from it.
			if err := rejectStagedPlaintext(root, workingCfg); err != nil {
				return err
			}
		}
		return nil
	}

	cfg, err := config.Parse(root, configData)
	if err != nil {
		return withExit(exitConfig, fmt.Errorf("staged config %s is invalid: %w", configRel, err))
	}
	if err := rejectStagedPlaintext(root, cfg); err != nil {
		return err
	}

	recipientsRel, err := repoRelative(root, p.Recipients)
	if err != nil {
		return withExit(exitConfig, err)
	}
	recipientsData, present, err := indexBlob(root, filepath.ToSlash(recipientsRel))
	if err != nil || !present {
		if err == nil {
			err = fmt.Errorf("staged recipients file %s is missing", filepath.ToSlash(recipientsRel))
		}
		return withExit(exitConfig, err)
	}
	rf, err := keys.ParseRecipients(recipientsData)
	if err != nil {
		return withExit(exitConfig, fmt.Errorf("staged recipients file is invalid: %w", err))
	}
	lockRel, err := repoRelative(root, p.Lock)
	if err != nil {
		return withExit(exitConfig, err)
	}
	lockData, present, err := indexBlob(root, filepath.ToSlash(lockRel))
	if err != nil || !present {
		if err == nil {
			err = fmt.Errorf("staged lock file %s is missing", filepath.ToSlash(lockRel))
		}
		return withExit(exitConfig, err)
	}

	var ciphertexts []crypt.LockBlobTarget
	ciphertextData := make(map[string][]byte, len(cfg.Files))
	for _, fp := range cfg.Files {
		data, exists, blobErr := indexBlob(root, filepath.ToSlash(fp.Ciphertext))
		if blobErr != nil || !exists {
			if blobErr == nil {
				blobErr = fmt.Errorf("staged ciphertext %s is missing", fp.Ciphertext)
			}
			return withExit(exitOutOfSync, blobErr)
		}
		ciphertexts = append(ciphertexts, crypt.LockBlobTarget{Ciphertext: fp.Ciphertext, Data: data})
		ciphertextData[fp.Ciphertext] = data
	}
	if err := crypt.VerifyLockBytes(lockData, ciphertexts, rf.Fingerprint()); err != nil {
		return withExit(exitOutOfSync, fmt.Errorf("staged lock verification failed: %w", err))
	}

	managed := map[string]bool{configRel: true, filepath.ToSlash(recipientsRel): true, filepath.ToSlash(lockRel): true}
	for _, fp := range cfg.Files {
		managed[filepath.ToSlash(fp.Ciphertext)] = true
	}
	managedChanged := false
	for path := range staged {
		if managed[path] {
			managedChanged = true
			break
		}
	}
	if !managedChanged {
		return nil // exact staged snapshot passed structural verification
	}

	id, err := keys.ResolveIdentity(flags.identity, keys.DefaultPrompter())
	if err != nil {
		return err
	}
	for _, fp := range cfg.Files {
		working, readErr := os.ReadFile(fp.CiphertextPath) //nolint:gosec // validated managed ciphertext
		if readErr != nil {
			return withExit(exitOutOfSync, fmt.Errorf("read working ciphertext %s: %w", fp.Ciphertext, readErr))
		}
		if !bytes.Equal(working, ciphertextData[fp.Ciphertext]) {
			return withExit(exitOutOfSync, fmt.Errorf("working and staged ciphertext differ for %s; stage the complete ciphertext and lock together", fp.Ciphertext))
		}
		_, sealed, decryptErr := crypt.DecryptBytesToDotenv(id.Identities, ciphertextData[fp.Ciphertext])
		if decryptErr != nil {
			return decryptErr
		}
		local, parseErr := parsePlaintext(fp.PlaintextPath)
		if parseErr != nil {
			return withExit(exitConfig, parseErr)
		}
		added, removed, changed := diffKeys(sealed, local)
		if len(added)+len(removed)+len(changed) != 0 {
			return withExit(exitOutOfSync, fmt.Errorf("%s is out of date with staged %s (added keys: %v; removed keys: %v; changed keys: %v); run `envguardian encrypt` and stage ciphertext plus lock", fp.Plaintext, fp.Ciphertext, added, removed, changed))
		}
	}
	return nil
}

func rejectStagedPlaintext(root string, cfg *config.Config) error {
	var leaking []string
	for _, fp := range cfg.Files {
		_, present, err := indexBlob(root, filepath.ToSlash(fp.Plaintext))
		if err != nil {
			return withExit(exitConfig, err)
		}
		if present {
			leaking = append(leaking, fp.Plaintext)
		}
	}
	if len(leaking) == 0 {
		return nil
	}
	return withExit(exitConfig, fmt.Errorf("refusing to commit plaintext secret file(s): %s\n  fix: `git rm --cached %s` and commit the ciphertext instead", strings.Join(leaking, ", "), strings.Join(leaking, " ")))
}

// stagedFiles returns the exact NUL-delimited paths changed in the index.
func stagedFiles(root string) (map[string]bool, error) {
	set := map[string]bool{}
	out, err := gitBytes(root, "diff", "--cached", "--name-only", "-z")
	if err != nil {
		return nil, err
	}
	for _, name := range bytes.Split(out, []byte{0}) {
		if len(name) != 0 {
			set[filepath.ToSlash(string(name))] = true
		}
	}
	return set, nil
}

func indexBlob(root, path string) ([]byte, bool, error) {
	listed, err := gitBytes(root, "ls-files", "--stage", "-z", "--", path)
	if err != nil {
		return nil, false, err
	}
	if len(listed) == 0 {
		return nil, false, nil
	}
	data, err := gitBytes(root, "show", ":"+path)
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}

func headBlob(root, path string) ([]byte, bool, error) {
	verify := exec.Command("git", "rev-parse", "--verify", "--quiet", "HEAD") // #nosec G204 -- fixed command
	verify.Dir = root
	if out, err := verify.CombinedOutput(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
			return nil, false, nil // legitimate unborn repository
		}
		return nil, false, fmt.Errorf("git rev-parse --verify HEAD: %w: %s", err, strings.TrimSpace(string(out)))
	}
	listed, err := gitBytes(root, "ls-tree", "-z", "--name-only", "HEAD", "--", path)
	if err != nil {
		return nil, false, err
	}
	if len(listed) == 0 {
		return nil, false, nil
	}
	data, err := gitBytes(root, "show", "HEAD:"+path)
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}
