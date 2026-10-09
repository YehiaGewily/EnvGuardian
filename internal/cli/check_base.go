package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/YehiaGewily/envguardian/internal/authenticity"
	"github.com/YehiaGewily/envguardian/internal/config"
	"github.com/YehiaGewily/envguardian/internal/keys"
)

// checkBaseProvenance compares the checked snapshot with a trusted base
// revision. Plain `check` verifies a snapshot against its own
// recipients.toml, so a pull request that adds its author as a recipient and
// re-seals with `encrypt --force` passes it. Against a base, every ciphertext
// that changed since the base must be signed by a recipient the base already
// trusted. Any Git error resolving or reading the base is a failure.
func checkBaseProvenance(p config.Paths, cfg *config.Config, base string) []checkResult {
	fail := func(detail string, code int) []checkResult {
		return []checkResult{{Name: "base " + base, Detail: detail, Code: code}}
	}
	if base == "" || strings.HasPrefix(base, "-") {
		return fail("base revision must be a commit, branch, or tag name and must not start with '-'", exitConfig)
	}
	commit, err := resolveCommit(p.Root, base)
	if err != nil {
		return fail(fmt.Sprintf("cannot resolve base revision; make sure it is fetched (in GitHub Actions, check out with fetch-depth: 0): %v", err), exitConfig)
	}
	recipientsRel, err := repoRelative(p.Root, p.Recipients)
	if err != nil {
		return fail(err.Error(), exitConfig)
	}
	baseRecipients, err := gitBlob(p.Root, commit, recipientsRel)
	if err != nil {
		return fail(fmt.Sprintf("cannot read the base recipients file: %v", err), exitConfig)
	}
	if !baseRecipients.Exists {
		return fail(fmt.Sprintf("base %s has no %s; review the first EnvGuardian adoption manually and run plain `check` for it", shortCommit(commit), recipientsRel), exitConfig)
	}
	baseRF, err := keys.ParseRecipients(baseRecipients.Data)
	if err != nil {
		return fail(fmt.Sprintf("base recipients file is invalid: %v", err), exitConfig)
	}
	currentData, err := os.ReadFile(p.Recipients)
	if err != nil {
		return fail(fmt.Sprintf("read current recipients file: %v", err), exitConfig)
	}
	rf, err := keys.ParseRecipients(currentData)
	if err != nil {
		return fail(fmt.Sprintf("current recipients file is invalid: %v", err), exitConfig)
	}

	var results []checkResult
	if bytes.Equal(currentData, baseRecipients.Data) {
		results = append(results, checkResult{Name: "base recipients", OK: true, Detail: "unchanged since base " + shortCommit(commit)})
	} else {
		changes := summarizeRecipientChanges(baseRecipients, gitBlobResult{Data: currentData, Exists: true})
		results = append(results, checkResult{Name: "base recipients", OK: true, Warning: true,
			Detail: fmt.Sprintf("changed since base %s (%s); require code-owner review and confirm the change out of band", shortCommit(commit), strings.Join(changes, "; "))})
	}
	for _, fp := range cfg.Files {
		results = append(results, checkCiphertextAgainstBase(p, fp, rf, baseRF, commit))
	}
	return results
}

func checkCiphertextAgainstBase(p config.Paths, fp config.FilePair, rf, baseRF *keys.RecipientsFile, commit string) checkResult {
	name := "base provenance " + fp.Ciphertext
	ciphertext, err := os.ReadFile(fp.CiphertextPath) //nolint:gosec // validated managed ciphertext path
	if err != nil {
		return checkResult{Name: name, Detail: fmt.Sprintf("cannot read ciphertext: %v", err)}
	}
	signature, err := os.ReadFile(fp.SignaturePath) //nolint:gosec // validated derived signature path
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return checkResult{Name: name, Detail: missingSignatureFailure, Code: exitSignature}
		}
		return checkResult{Name: name, Detail: fmt.Sprintf("cannot read signature: %v", err)}
	}
	baseCiphertext, err := gitBlob(p.Root, commit, fp.Ciphertext)
	if err != nil {
		return checkResult{Name: name, Detail: fmt.Sprintf("cannot read base ciphertext: %v", err), Code: exitConfig}
	}
	baseSignature, err := gitBlob(p.Root, commit, authenticity.SignatureName(fp.Ciphertext))
	if err != nil {
		return checkResult{Name: name, Detail: fmt.Sprintf("cannot read base signature: %v", err), Code: exitConfig}
	}
	if sameGitBlob(baseCiphertext, gitBlobResult{Data: ciphertext, Exists: true}) && sameGitBlob(baseSignature, gitBlobResult{Data: signature, Exists: true}) {
		return checkResult{Name: name, OK: true, Detail: "unchanged since base " + shortCommit(commit)}
	}
	binding, err := signatureBinding(p, fp, rf.Fingerprint())
	if err != nil {
		return checkResult{Name: name, Detail: err.Error(), Code: exitConfig}
	}
	signer, err := authenticity.Verify(signature, baseRF, binding, ciphertext)
	if err != nil {
		return checkResult{Name: name, Code: exitSignature,
			Detail: fmt.Sprintf("changed since base %s but not signed by a recipient trusted at base: %v", shortCommit(commit), err)}
	}
	return checkResult{Name: name, OK: true, Detail: fmt.Sprintf("changed since base %s; signed by base recipient %q", shortCommit(commit), signer)}
}
