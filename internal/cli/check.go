package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"filippo.io/age"
	"github.com/BurntSushi/toml"
	"github.com/spf13/cobra"

	"github.com/YehiaGewily/envguardian/internal/config"
	"github.com/YehiaGewily/envguardian/internal/crypt"
	"github.com/YehiaGewily/envguardian/internal/gitint"
	"github.com/YehiaGewily/envguardian/internal/keys"
)

// checkResult is one line of check output.
type checkResult struct {
	Name    string `json:"name"`
	OK      bool   `json:"ok"`
	Skipped bool   `json:"skipped,omitempty"`
	Warning bool   `json:"warning,omitempty"`
	Detail  string `json:"detail,omitempty"`
	Code    int    `json:"-"`
}

func (r checkResult) failed() bool { return !r.OK && !r.Skipped }

func newCheckCmd(flags *globalFlags) *cobra.Command {
	var structuralOnly bool
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Verify committed repository integrity (CI mode)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCheck(cmd, flags, structuralOnly)
		},
	}
	cmd.Flags().BoolVar(&structuralOnly, "structural-only", false, "verify public repository structure without decrypting ciphertext")
	return cmd
}

func newCheckLocalCmd(flags *globalFlags) *cobra.Command {
	var allowMissing bool
	cmd := &cobra.Command{
		Use:   "check-local",
		Short: "Verify local plaintext is synchronized with ciphertext",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCheckLocal(cmd, flags, allowMissing)
		},
	}
	cmd.Flags().BoolVar(&allowMissing, "allow-missing", false, "allow a missing local plaintext file")
	return cmd
}

func runCheck(cmd *cobra.Command, flags *globalFlags, structuralOnly bool) error {
	p, err := secureRootPaths(flags)
	if err != nil {
		return err
	}
	results, _, identityErr := collectRepositoryChecks(p, flags, structuralOnly)
	if err := printCheckResults(cmd, flags, results); err != nil {
		return err
	}
	if identityErr != nil {
		return identityErr
	}
	return checkFailure(results)
}

func runCheckLocal(cmd *cobra.Command, flags *globalFlags, allowMissing bool) error {
	p, err := secureRootPaths(flags)
	if err != nil {
		return err
	}
	results, cfg, identityErr := collectRepositoryChecks(p, flags, false)
	if identityErr != nil {
		_ = printCheckResults(cmd, flags, results)
		return identityErr
	}
	if cfg != nil {
		id, resolveErr := keys.ResolveIdentity(flags.identity, keys.DefaultPrompter())
		if resolveErr != nil {
			_ = printCheckResults(cmd, flags, results)
			return resolveErr
		}
		for _, fp := range cfg.Files {
			results = append(results, checkLocalPair(fp, id.Identities, allowMissing))
		}
	}
	if err := printCheckResults(cmd, flags, results); err != nil {
		return err
	}
	return checkFailure(results)
}

// collectRepositoryChecks verifies only repository state. It deliberately
// never reads local plaintext contents: CI cannot establish whether an
// uncommitted developer file is current.
func collectRepositoryChecks(p config.Paths, flags *globalFlags, structuralOnly bool) ([]checkResult, *config.Config, error) {
	var results []checkResult
	cfg, cfgErr := config.Load(p.Root, p.Config)
	if cfgErr != nil {
		results = append(results, checkResult{Name: "config", Detail: cfgErr.Error(), Code: exitConfig})
	} else {
		results = append(results, checkResult{Name: "config", OK: true, Detail: fmt.Sprintf("version %d; managed paths are safe", cfg.Version)})
	}

	rf, recipientsErr := keys.LoadRecipients(p.Recipients)
	if recipientsErr != nil {
		results = append(results, checkResult{Name: "recipients", Detail: recipientsErr.Error(), Code: exitConfig})
	} else {
		results = append(results, checkResult{Name: "recipients", OK: true, Detail: fmt.Sprintf("%d recipient(s), well-formed", len(rf.Recipients))})
	}

	if cfg != nil && rf != nil {
		targets := make([]crypt.LockTarget, 0, len(cfg.Files))
		for _, fp := range cfg.Files {
			targets = append(targets, crypt.LockTarget{Ciphertext: fp.Ciphertext, Path: fp.CiphertextPath})
		}
		if err := crypt.VerifyLock(p.Lock, targets, rf.Fingerprint()); err != nil {
			results = append(results, checkResult{Name: "lock", Detail: err.Error()})
		} else {
			results = append(results, checkResult{Name: "lock", OK: true, Detail: "digest and recipient fingerprint match"})
		}
		for _, fp := range cfg.Files {
			results = append(results, checkCiphertextSignature(p, fp, rf))
		}
	}

	if cfg != nil {
		for _, fp := range cfg.Files {
			results = append(results, checkGitignore(p.Root, fp.Plaintext))
		}
	}
	results = append(results, checkRotations(p))

	if cfg == nil {
		return results, nil, nil
	}
	if structuralOnly {
		results = append(results, checkResult{Name: "ciphertext contents", OK: true, Skipped: true, Detail: "explicit --structural-only mode; decryption not attempted"})
		return results, cfg, nil
	}
	id, err := keys.ResolveIdentity(flags.identity, keys.DefaultPrompter())
	if err != nil {
		results = append(results, checkResult{Name: "ciphertext contents", Detail: "identity is required; use --structural-only only when secrets are unavailable"})
		return results, cfg, err
	}
	for _, fp := range cfg.Files {
		results = append(results, checkCiphertextContents(fp, id.Identities))
	}
	return results, cfg, nil
}

func checkCiphertextSignature(p config.Paths, fp config.FilePair, rf *keys.RecipientsFile) checkResult {
	name := "signature " + fp.Ciphertext + ".sig"
	ciphertext, err := os.ReadFile(fp.CiphertextPath) //nolint:gosec // validated managed ciphertext path
	if err != nil {
		return checkResult{Name: name, Detail: fmt.Sprintf("cannot read ciphertext for signature verification: %v", err)}
	}
	signer, missing, err := verifyCiphertextSignature(p, fp, rf, ciphertext)
	if err != nil {
		return checkResult{Name: name, Detail: err.Error(), Code: exitSignature}
	}
	if missing {
		return checkResult{Name: name, OK: true, Warning: true, Detail: unsignedMigrationWarning}
	}
	return checkResult{Name: name, OK: true, Detail: fmt.Sprintf("valid; signed by current recipient %q", signer)}
}

func checkGitignore(root, plaintext string) checkResult {
	ig, err := gitint.IsIgnored(root, plaintext)
	switch {
	case err != nil:
		return checkResult{Name: "gitignore " + plaintext, Detail: err.Error()}
	case ig:
		return checkResult{Name: "gitignore " + plaintext, OK: true, Detail: "ignored"}
	default:
		return checkResult{Name: "gitignore " + plaintext, Detail: "plaintext is NOT gitignored"}
	}
}

func checkCiphertextContents(fp config.FilePair, identities []age.Identity) checkResult {
	data, err := os.ReadFile(fp.CiphertextPath) //nolint:gosec // validated managed ciphertext path
	if err != nil {
		return checkResult{Name: "ciphertext " + fp.Ciphertext, Detail: fmt.Sprintf("cannot read ciphertext: %v", err)}
	}
	if _, _, err := crypt.DecryptBytesToDotenv(identities, data); err != nil {
		code := exitIdentity
		var invalid *crypt.InvalidDotenvError
		if errors.As(err, &invalid) {
			code = exitConfig
		}
		return checkResult{Name: "ciphertext " + fp.Ciphertext, Detail: err.Error(), Code: code}
	}
	return checkResult{Name: "ciphertext " + fp.Ciphertext, OK: true, Detail: "decrypts and contains valid dotenv"}
}

func checkLocalPair(fp config.FilePair, identities []age.Identity, allowMissing bool) checkResult {
	name := "local " + fp.Plaintext
	local, err := parsePlaintext(fp.PlaintextPath)
	if err != nil {
		if allowMissing && errors.Is(err, os.ErrNotExist) {
			return checkResult{Name: name, OK: true, Skipped: true, Detail: "missing; explicitly allowed"}
		}
		code := exitConfig
		if errors.Is(err, os.ErrNotExist) {
			code = exitOutOfSync
		}
		return checkResult{Name: name, Detail: err.Error(), Code: code}
	}
	ciphertext, err := os.ReadFile(fp.CiphertextPath) //nolint:gosec // validated managed ciphertext path
	if err != nil {
		return checkResult{Name: name, Detail: fmt.Sprintf("read ciphertext %s: %v", fp.Ciphertext, err)}
	}
	_, sealed, err := crypt.DecryptBytesToDotenv(identities, ciphertext)
	if err != nil {
		code := exitIdentity
		var invalid *crypt.InvalidDotenvError
		if errors.As(err, &invalid) {
			code = exitConfig
		}
		return checkResult{Name: name, Detail: err.Error(), Code: code}
	}
	added, removed, changed := diffKeys(sealed, local)
	if len(added)+len(removed)+len(changed) != 0 {
		return checkResult{Name: name, Detail: fmt.Sprintf("out of sync (added keys: %v; removed keys: %v; changed keys: %v)", added, removed, changed)}
	}
	return checkResult{Name: name, OK: true, Detail: "matches ciphertext"}
}

func checkRotations(p config.Paths) checkResult {
	candidate := filepath.Join(p.Dir, "rotation.toml")
	rel, err := filepath.Rel(p.Root, candidate)
	if err != nil {
		return checkResult{Name: "rotations", Detail: fmt.Sprintf("resolve rotation ledger path: %v", err), Code: exitConfig}
	}
	path, err := config.ResolveManagedPath(p.Root, filepath.ToSlash(rel))
	if err != nil {
		return checkResult{Name: "rotations", Detail: fmt.Sprintf("unsafe rotation ledger path: %v", err), Code: exitConfig}
	}
	data, err := os.ReadFile(path) //nolint:gosec // validated repository metadata path
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return checkResult{Name: "rotations", OK: true, Detail: "ledger absent; none pending"}
		}
		return checkResult{Name: "rotations", Detail: fmt.Sprintf("cannot read rotation ledger: %v", err), Code: exitConfig}
	}
	var rot struct {
		Pending []struct {
			Key string `toml:"key"`
		} `toml:"pending"`
	}
	metadata, err := toml.Decode(string(data), &rot)
	if err != nil {
		return checkResult{Name: "rotations", Detail: "rotation.toml is malformed", Code: exitConfig}
	}
	if undecoded := metadata.Undecoded(); len(undecoded) > 0 {
		return checkResult{Name: "rotations", Detail: fmt.Sprintf("rotation.toml has unknown field %q", undecoded[0].String()), Code: exitConfig}
	}
	if len(rot.Pending) == 0 {
		return checkResult{Name: "rotations", OK: true, Detail: "none pending"}
	}
	keyNames := make([]string, len(rot.Pending))
	for i, pending := range rot.Pending {
		keyNames[i] = pending.Key
	}
	return checkResult{Name: "rotations", Detail: fmt.Sprintf("%d pending keys: %v", len(rot.Pending), keyNames)}
}

func printCheckResults(cmd *cobra.Command, flags *globalFlags, results []checkResult) error {
	failed := 0
	for _, result := range results {
		if result.failed() {
			failed++
		}
	}
	out := cmd.OutOrStdout()
	if flags.json {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(struct {
			OK      bool          `json:"ok"`
			Failed  int           `json:"failed"`
			Results []checkResult `json:"results"`
		}{OK: failed == 0, Failed: failed, Results: results})
	}
	for _, result := range results {
		tag := "OK  "
		switch {
		case result.Skipped:
			tag = "SKIP"
		case result.Warning:
			tag = "WARN"
		case !result.OK:
			tag = "FAIL"
		}
		if result.Detail == "" {
			fmt.Fprintf(out, "[%s] %s\n", tag, result.Name)
		} else {
			fmt.Fprintf(out, "[%s] %s — %s\n", tag, result.Name, result.Detail)
		}
	}
	return nil
}

func checkFailure(results []checkResult) error {
	failed := 0
	code := exitOutOfSync
	signatureFailure := false
	nonSignatureFailure := false
	for _, result := range results {
		if !result.failed() {
			continue
		}
		failed++
		if result.Code == exitSignature {
			signatureFailure = true
			continue
		}
		nonSignatureFailure = true
		if result.Code == exitIdentity {
			code = exitIdentity
		} else if result.Code == exitConfig && code != exitIdentity {
			code = exitConfig
		}
	}
	if failed == 0 {
		return nil
	}
	if signatureFailure && !nonSignatureFailure {
		code = exitSignature
	}
	return withExit(code, fmt.Errorf("%d check(s) failed", failed))
}
