// Command envguardian is the CLI entry point for EnvGuardian.
package main

import (
	"os"

	"github.com/YehiaGewily/envguardian/internal/cli"
)

// Build metadata, injected at release time via -ldflags. See the Makefile.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	os.Exit(cli.Execute(cli.BuildInfo{
		Version: version,
		Commit:  commit,
		Date:    date,
	}))
}
