package cli

import (
	"github.com/spf13/cobra"
)

// newVersionCmd prints the build metadata baked in at release time.
func newVersionCmd(info BuildInfo) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version, commit, and build date",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.Printf("envguardian %s (commit %s, built %s)\n",
				info.Version, info.Commit, info.Date)
			return nil
		},
	}
}
