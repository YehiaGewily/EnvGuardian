// Package cli wires up the cobra command tree for EnvGuardian.
//
// It owns flag definitions and command dispatch only. Command logic lives in
// the internal packages (dotenv, keys, crypt, gitint, rotation) so that this
// package stays a thin presentation layer.
package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// BuildInfo carries version metadata injected at build time.
type BuildInfo struct {
	Version string
	Commit  string
	Date    string
}

// globalFlags holds the persistent flags shared by every subcommand. They are
// wired here but not yet consumed; command logic will read them as it lands.
type globalFlags struct {
	identity string
	config   string
	json     bool
	noColor  bool
	verbose  bool
}

// newRootCmd builds the root command and attaches all subcommands.
func newRootCmd(info BuildInfo) *cobra.Command {
	var flags globalFlags

	root := &cobra.Command{
		Use:   "envguardian",
		Short: "Commit your team's .env to git, encrypted.",
		Long: "EnvGuardian encrypts your .env to every developer's age/SSH public key and\n" +
			"commits the ciphertext, so cloning or pulling the repo is all it takes to\n" +
			"have working local configuration. Access is a reviewable recipients file.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	pf := root.PersistentFlags()
	pf.StringVar(&flags.identity, "identity", "", "path to the age/SSH identity to decrypt with")
	pf.StringVar(&flags.config, "config", "", "path to the EnvGuardian config file")
	pf.BoolVar(&flags.json, "json", false, "emit machine-readable JSON output")
	pf.BoolVar(&flags.noColor, "no-color", false, "disable colored output")
	pf.BoolVarP(&flags.verbose, "verbose", "v", false, "verbose output")

	root.AddCommand(newVersionCmd(info))

	return root
}

// Execute runs the CLI and returns a process exit code.
func Execute(info BuildInfo) int {
	if err := newRootCmd(info).Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "envguardian:", err)
		return 1
	}
	return 0
}
