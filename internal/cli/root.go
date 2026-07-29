// Package cli wires up the cobra command tree for EnvGuardian.
//
// It owns flag definitions, command dispatch, and the mapping of errors to exit
// codes. Command logic lives in the internal packages (dotenv, keys, crypt,
// config) so this package stays a thin presentation layer.
package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/YehiaGewily/envguardian/internal/crypt"
	"github.com/YehiaGewily/envguardian/internal/dotenv"
	"github.com/YehiaGewily/envguardian/internal/keys"
)

// Exit codes are part of the current CLI contract.
const (
	exitOK        = 0
	exitOutOfSync = 1
	exitIdentity  = 2
	exitConfig    = 3
)

// BuildInfo carries version metadata injected at build time.
type BuildInfo struct {
	Version string
	Commit  string
	Date    string
}

// globalFlags holds the persistent flags shared by every subcommand.
type globalFlags struct {
	identity string
	config   string
	json     bool
	verbose  bool
}

// exitError attaches a specific exit code to an error.
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string { return e.err.Error() }
func (e *exitError) Unwrap() error { return e.err }

func withExit(code int, err error) error {
	if err == nil {
		return nil
	}
	return &exitError{code: code, err: err}
}

// newRootCmd builds the root command and attaches all subcommands.
func newRootCmd(info BuildInfo) *cobra.Command {
	flags := &globalFlags{}

	root := &cobra.Command{
		Use:   "envguardian",
		Short: "Commit your team's .env to git, encrypted.",
		Long: "EnvGuardian encrypts your .env to every developer's age/SSH public key and\n" +
			"commits the ciphertext, so cloning or pulling the repo is all it takes to\n" +
			"have working local configuration. Access is a reviewable recipients file.",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			if flags.json && cmd.Name() != "check" && cmd.Name() != "list-recipients" {
				return withExit(exitConfig, fmt.Errorf("--json is not supported by %q; use it only with check or list-recipients", cmd.Name()))
			}
			if flags.verbose {
				fmt.Fprintf(cmd.ErrOrStderr(), "envguardian: verbose: command=%s\n", cmd.Name())
			}
			return nil
		},
	}

	pf := root.PersistentFlags()
	pf.StringVar(&flags.identity, "identity", "", "path to the age/SSH identity to decrypt with")
	pf.StringVar(&flags.config, "config", "", "path to the EnvGuardian config file")
	pf.BoolVar(&flags.json, "json", false, "emit machine-readable JSON output")
	pf.BoolVarP(&flags.verbose, "verbose", "v", false, "report command progress without secret values")

	root.AddCommand(
		newVersionCmd(info),
		newInitCmd(flags),
		newEncryptCmd(flags),
		newDecryptCmd(flags),
		newAddRecipientCmd(flags),
		newListRecipientsCmd(flags),
		newCheckCmd(flags),
		newCheckLocalCmd(flags),
		newInstallHooksCmd(flags),
		newHookAutoDecryptCmd(flags),
		newHookPreCommitCmd(flags),
		newDiffCmd(flags),
		newDiffDriverCmd(flags),
	)

	return root
}

// Execute runs the CLI and returns a process exit code.
func Execute(info BuildInfo) int {
	if err := newRootCmd(info).Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "envguardian:", err)
		return exitCodeFor(err)
	}
	return exitOK
}

// exitCodeFor maps an error to an exit code. Identity/decrypt failures take
// precedence (2), then any explicit code, else a generic failure (1).
func exitCodeFor(err error) int {
	var decryptErr *crypt.DecryptError
	var identityRequired *crypt.IdentityRequiredError
	if errors.As(err, &decryptErr) || errors.As(err, &identityRequired) {
		return exitIdentity
	}
	if errors.Is(err, keys.ErrPassphraseRequired) || errors.Is(err, crypt.ErrNotARecipient) {
		return exitIdentity
	}
	var nie *keys.NoIdentityError
	if errors.As(err, &nie) {
		return exitIdentity
	}
	var invalidDecrypted *crypt.InvalidDotenvError
	var invalidPlaintext *crypt.InvalidPlaintextError
	var parseErr *dotenv.ParseError
	if errors.As(err, &invalidDecrypted) || errors.As(err, &invalidPlaintext) || errors.As(err, &parseErr) {
		return exitConfig
	}
	var ee *exitError
	if errors.As(err, &ee) {
		return ee.code
	}
	return exitOutOfSync
}
