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

	"github.com/YehiaGewily/envguardian/internal/authenticity"
	"github.com/YehiaGewily/envguardian/internal/config"
	"github.com/YehiaGewily/envguardian/internal/keys"
)

func newDoctorCmd(flags *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Diagnose the local setup without decrypting anything",
		Long: "Report config and recipients validity, ssh-keygen availability, ciphertext\n" +
			".gitattributes rules, hook and driver installation (and whether the binary\n" +
			"they record still exists), and accepted-commit trust state. doctor never\n" +
			"decrypts and never prints values. It exits non-zero when anything is broken.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runDoctor(cmd, flags)
		},
	}
}

func runDoctor(cmd *cobra.Command, flags *globalFlags) error {
	p, err := secureRootPaths(flags)
	if err != nil {
		return err
	}
	var results []checkResult
	cfg, cfgErr := config.Load(p.Root, p.Config)
	if cfgErr != nil {
		results = append(results, checkResult{Name: "config", Detail: cfgErr.Error(), Code: exitConfig})
	} else {
		results = append(results, checkResult{Name: "config", OK: true, Detail: fmt.Sprintf("%d managed file(s); paths are safe", len(cfg.Files))})
	}
	if rf, rfErr := keys.LoadRecipients(p.Recipients); rfErr != nil {
		results = append(results, checkResult{Name: "recipients", Detail: rfErr.Error(), Code: exitConfig})
	} else {
		results = append(results, checkResult{Name: "recipients", OK: true, Detail: fmt.Sprintf("%d recipient(s), well-formed", len(rf.Recipients))})
	}
	if _, lookErr := exec.LookPath("ssh-keygen"); lookErr != nil {
		results = append(results, checkResult{Name: "ssh-keygen", Detail: "not found on PATH; install OpenSSH, which signs and verifies ciphertext"})
	} else {
		results = append(results, checkResult{Name: "ssh-keygen", OK: true, Detail: "available"})
	}

	root, inRepo, gitErr := gitWorkTree(p.Root)
	switch {
	case gitErr != nil:
		results = append(results, checkResult{Name: "git", Detail: gitErr.Error()})
	case !inRepo:
		results = append(results, checkResult{Name: "git", OK: true, Skipped: true, Detail: "not a Git repository; hooks, drivers, attributes, and trust state do not apply"})
	default:
		if cfg != nil {
			for _, fp := range cfg.Files {
				results = append(results, checkGitignore(root, fp.Plaintext))
				results = append(results, doctorTextAttribute(root, fp.Ciphertext), doctorTextAttribute(root, authenticity.SignatureName(fp.Ciphertext)))
			}
		}
		results = append(results, doctorHooks(root)...)
		results = append(results, doctorDrivers(root)...)
		results = append(results, doctorTrustState(root, p, cfg))
	}
	if err := printCheckResults(cmd, flags, results); err != nil {
		return err
	}
	return checkFailure(results)
}

// doctorTextAttribute requires `-text` on ciphertext and signatures: both are
// verified byte for byte, so line-ending conversion breaks a teammate's clone.
func doctorTextAttribute(root, rel string) checkResult {
	name := "attributes " + rel
	out, err := gitCommandBytes(root, "check-attr", "-z", "text", "--", filepath.ToSlash(rel))
	if err != nil {
		return checkResult{Name: name, Detail: fmt.Sprintf("cannot read Git attributes: %v", err)}
	}
	fields := bytes.Split(out, []byte{0})
	if len(fields) >= 3 && string(fields[2]) == "unset" {
		return checkResult{Name: name, OK: true, Detail: "-text (no line-ending conversion)"}
	}
	return checkResult{Name: name, Detail: "Git may convert line endings; add `*.age -text` and `*.age.sig -text` to .gitattributes and commit it"}
}

func doctorHooks(root string) []checkResult {
	dir, err := hooksDir(root)
	if err != nil {
		return []checkResult{{Name: "hooks", Detail: err.Error()}}
	}
	results := make([]checkResult, 0, len(managedHooks))
	for _, hook := range managedHooks {
		name := "hook " + hook
		data, readErr := os.ReadFile(filepath.Join(dir, hook)) //nolint:gosec // git hook path under the repository
		if errors.Is(readErr, os.ErrNotExist) || (readErr == nil && !bytes.Contains(data, []byte(hookBegin))) {
			results = append(results, checkResult{Name: name, OK: true, Skipped: true, Detail: "not installed (optional: envguardian install-hooks)"})
			continue
		}
		if readErr != nil {
			results = append(results, checkResult{Name: name, Detail: fmt.Sprintf("cannot read hook: %v", readErr)})
			continue
		}
		recorded, ok := recordedHookBinary(string(data))
		if !ok {
			results = append(results, checkResult{Name: name, Detail: "installed by an older EnvGuardian; run `envguardian install-hooks` to update it"})
			continue
		}
		results = append(results, recordedBinaryResult(name, recorded, "envguardian install-hooks"))
	}
	return results
}

// recordedHookBinary extracts the binary path from the managed block's
// envguardian_bin assignment.
func recordedHookBinary(content string) (string, bool) {
	for _, line := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		if value, found := strings.CutPrefix(line, "envguardian_bin="); found {
			word, _, ok := shellWord(value)
			return word, ok
		}
	}
	return "", false
}

func doctorDrivers(root string) []checkResult {
	drivers := []struct{ key, reinstall string }{
		{"diff.envguardian.command", "envguardian diff --install"},
		{"merge.envguardian.driver", "envguardian merge --install"},
		{"merge.envguardian-generated.driver", "envguardian merge --install"},
	}
	results := make([]checkResult, 0, len(drivers))
	for _, driver := range drivers {
		name := "driver " + driver.key
		value := gitOutput(root, "config", "--local", "--get", driver.key)
		if value == "" {
			results = append(results, checkResult{Name: name, OK: true, Skipped: true, Detail: "not installed (optional: " + driver.reinstall + ")"})
			continue
		}
		binary, _, ok := shellWord(value)
		if !ok {
			results = append(results, checkResult{Name: name, Detail: "command is not a quoted EnvGuardian binary; run `" + driver.reinstall + "`"})
			continue
		}
		results = append(results, recordedBinaryResult(name, binary, driver.reinstall))
	}
	return results
}

func recordedBinaryResult(name, binary, reinstall string) checkResult {
	info, err := os.Stat(filepath.FromSlash(binary)) //nolint:gosec // G703: stat only; a locally recorded hook/driver path is never read or run here
	if err != nil || info.IsDir() {
		return checkResult{Name: name, Detail: fmt.Sprintf("recorded binary %s is missing; run `%s` with the installed binary", binary, reinstall)}
	}
	return checkResult{Name: name, OK: true, Detail: "runs " + binary}
}

// shellWord parses one POSIX shell word made of plain characters,
// single-quoted segments, and double-quoted segments without escapes, which
// covers everything shellQuote produces. It returns the word and the rest.
func shellWord(value string) (string, string, bool) {
	value = strings.TrimLeft(value, " \t")
	var word strings.Builder
	i := 0
	for i < len(value) {
		switch c := value[i]; c {
		case ' ', '\t':
			return word.String(), value[i:], word.Len() > 0
		case '\'', '"':
			end := strings.IndexByte(value[i+1:], c)
			if end < 0 {
				return "", "", false
			}
			word.WriteString(value[i+1 : i+1+end])
			i += end + 2
		case '\\', '$', '`':
			return "", "", false
		default:
			word.WriteByte(c)
			i++
		}
	}
	return word.String(), "", word.Len() > 0
}

// doctorTrustState reports the accepted commit and whether HEAD's managed
// files still match it. It reads only committed blobs and never decrypts.
func doctorTrustState(root string, p config.Paths, cfg *config.Config) checkResult {
	const name = "trust state"
	state, err := loadAutoDecryptState(p.State)
	if errors.Is(err, os.ErrNotExist) {
		return checkResult{Name: name, OK: true, Warning: true, Detail: "no accepted commit recorded; review HEAD, then run `envguardian decrypt --accept-changes`"}
	}
	if err != nil {
		return checkResult{Name: name, Detail: fmt.Sprintf("unreadable %s: %v", config.AutoDecryptStateRelative, err)}
	}
	if cfg == nil {
		return checkResult{Name: name, OK: true, Detail: "accepted commit " + shortCommit(state.Commit)}
	}
	head, err := resolveCommit(root, "HEAD")
	if err != nil {
		return checkResult{Name: name, OK: true, Warning: true, Detail: "accepted commit " + shortCommit(state.Commit) + "; HEAD cannot be resolved"}
	}
	paths := []string{p.Config, p.Recipients}
	for _, fp := range cfg.Files {
		paths = append(paths, fp.CiphertextPath, fp.SignaturePath)
	}
	for _, path := range paths {
		rel, relErr := repoRelative(root, path)
		if relErr != nil {
			return checkResult{Name: name, Detail: relErr.Error()}
		}
		accepted, acceptedErr := gitBlob(root, state.Commit, rel)
		current, currentErr := gitBlob(root, head, rel)
		if acceptedErr != nil || currentErr != nil {
			return checkResult{Name: name, OK: true, Warning: true, Detail: "accepted commit " + shortCommit(state.Commit) + " is not readable in this clone; review HEAD, then run `envguardian decrypt --accept-changes`"}
		}
		if !sameGitBlob(accepted, current) {
			return checkResult{Name: name, OK: true, Warning: true, Detail: fmt.Sprintf("HEAD's %s differs from accepted commit %s; review it, then run `envguardian decrypt --accept-changes`", filepath.ToSlash(rel), shortCommit(state.Commit))}
		}
	}
	return checkResult{Name: name, OK: true, Detail: "HEAD matches accepted commit " + shortCommit(state.Commit)}
}
