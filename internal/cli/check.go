package cli

import (
	"encoding/json"
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

// checkResult is one line of `check` output.
type checkResult struct {
	Name    string `json:"name"`
	OK      bool   `json:"ok"`
	Skipped bool   `json:"skipped,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

func (r checkResult) failed() bool { return !r.OK && !r.Skipped }

func newCheckCmd(flags *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "check",
		Short: "Verify the repo is in sync (CI mode)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCheck(cmd, flags)
		},
	}
}

func runCheck(cmd *cobra.Command, flags *globalFlags) error {
	p := rootPaths(flags)
	results := collectChecks(p, flags)

	failed := 0
	for _, r := range results {
		if r.failed() {
			failed++
		}
	}

	out := cmd.OutOrStdout()
	if flags.json {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(struct {
			OK      bool          `json:"ok"`
			Failed  int           `json:"failed"`
			Results []checkResult `json:"results"`
		}{OK: failed == 0, Failed: failed, Results: results}); err != nil {
			return err
		}
	} else {
		for _, r := range results {
			tag := "OK  "
			switch {
			case r.Skipped:
				tag = "SKIP"
			case !r.OK:
				tag = "FAIL"
			}
			if r.Detail != "" {
				fmt.Fprintf(out, "[%s] %s — %s\n", tag, r.Name, r.Detail)
			} else {
				fmt.Fprintf(out, "[%s] %s\n", tag, r.Name)
			}
		}
	}

	if failed > 0 {
		return withExit(exitOutOfSync, fmt.Errorf("%d check(s) failed", failed))
	}
	return nil
}

// collectChecks runs every verification and returns one result per check,
// reporting all failures rather than stopping at the first.
func collectChecks(p config.Paths, flags *globalFlags) []checkResult {
	var results []checkResult

	cfg, cfgErr := config.Load(p.Root, p.Config)
	if cfgErr != nil {
		results = append(results, checkResult{Name: "config", Detail: cfgErr.Error()})
	} else {
		supported := cfg.Version >= 1 && cfg.Version <= config.Version
		results = append(results, checkResult{
			Name:   "config version",
			OK:     supported,
			Detail: fmt.Sprintf("version %d (supported: 1..%d)", cfg.Version, config.Version),
		})
	}

	rf, rErr := keys.LoadRecipients(p.Recipients)
	if rErr != nil {
		results = append(results, checkResult{Name: "recipients", Detail: rErr.Error()})
	} else {
		results = append(results, checkResult{
			Name: "recipients", OK: true,
			Detail: fmt.Sprintf("%d recipient(s), well-formed", len(rf.Recipients)),
		})
		if err := crypt.VerifyLock(p.Lock, rf.Fingerprint()); err != nil {
			results = append(results, checkResult{Name: "recipient set in sync", Detail: err.Error()})
		} else {
			results = append(results, checkResult{Name: "recipient set in sync", OK: true, Detail: "lock matches recipients"})
		}
	}

	if cfg != nil {
		var identities []keys.Identity
		if id, err := keys.ResolveIdentity(flags.identity, keys.DefaultPrompter()); err == nil {
			identities = []keys.Identity{*id}
		}
		var ageIDs []age.Identity
		if len(identities) > 0 {
			ageIDs = identities[0].Identities
		}
		for _, fp := range cfg.Files {
			results = append(results, checkGitignore(p.Root, fp.Plaintext))
			results = append(results, checkCiphertext(p, fp, ageIDs))
		}
	}

	results = append(results, checkRotations(p))
	return results
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

func checkCiphertext(p config.Paths, fp config.FilePair, ageIDs []age.Identity) checkResult {
	name := "ciphertext " + fp.Ciphertext
	st, err := crypt.Inspect(ageIDs, fp.CiphertextPath, fp.PlaintextPath)
	switch {
	case err != nil:
		return checkResult{Name: name, Detail: err.Error()}
	case !st.CiphertextExists:
		return checkResult{Name: name, Detail: "not encrypted yet (run `envguardian encrypt`)"}
	case len(ageIDs) == 0:
		return checkResult{Name: name, OK: true, Skipped: true, Detail: "present; no identity to verify contents"}
	case !st.Decryptable:
		return checkResult{Name: name, Detail: "cannot decrypt with the available identity"}
	case !st.PlaintextExists:
		return checkResult{Name: name, OK: true, Skipped: true, Detail: "decryptable; no local plaintext to compare"}
	case !st.Matches:
		return checkResult{Name: name, Detail: "STALE: plaintext changed but was not re-encrypted"}
	default:
		return checkResult{Name: name, OK: true, Detail: "matches plaintext"}
	}
}

func checkRotations(p config.Paths) checkResult {
	path := filepath.Join(p.Dir, "rotation.toml")
	data, err := os.ReadFile(path) //nolint:gosec // G304: repo rotation ledger
	if err != nil {
		return checkResult{Name: "rotations", OK: true, Detail: "none pending"}
	}
	var rot struct {
		Pending []struct {
			Key string `toml:"key"`
		} `toml:"pending"`
	}
	if err := toml.Unmarshal(data, &rot); err != nil {
		return checkResult{Name: "rotations", Detail: "rotation.toml is malformed"}
	}
	if len(rot.Pending) == 0 {
		return checkResult{Name: "rotations", OK: true, Detail: "none pending"}
	}
	keyNames := make([]string, len(rot.Pending))
	for i, pd := range rot.Pending {
		keyNames[i] = pd.Key
	}
	return checkResult{Name: "rotations", Detail: fmt.Sprintf("%d pending: %v (rotate each credential at its source)", len(rot.Pending), keyNames)}
}
