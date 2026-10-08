// Command envguardian is the CLI entry point for EnvGuardian.
package main

import (
	"os"
	"runtime/debug"

	"github.com/YehiaGewily/envguardian/internal/cli"
)

// Defaults for builds that inject no metadata, such as `go install`.
const (
	defaultVersion = "dev"
	defaultCommit  = "none"
	defaultDate    = "unknown"
)

// Build metadata, injected at release time via -ldflags. See the Makefile.
var (
	version = defaultVersion
	commit  = defaultCommit
	date    = defaultDate
)

func main() {
	embedded, _ := debug.ReadBuildInfo()
	os.Exit(cli.Execute(resolveBuildInfo(version, commit, date, embedded)))
}

// resolveBuildInfo returns the metadata to report. A value injected through
// -ldflags always wins. A field still at its default falls back to what the Go
// toolchain embedded in the binary: the main module version (for example
// v0.2.1 from `go install ...@v0.2.1`), vcs.revision, and vcs.time.
func resolveBuildInfo(version, commit, date string, embedded *debug.BuildInfo) cli.BuildInfo {
	info := cli.BuildInfo{Version: version, Commit: commit, Date: date}
	if embedded == nil {
		return info
	}
	if info.Version == defaultVersion && embedded.Main.Version != "" && embedded.Main.Version != "(devel)" {
		info.Version = embedded.Main.Version
	}
	for _, setting := range embedded.Settings {
		switch {
		case setting.Key == "vcs.revision" && info.Commit == defaultCommit && setting.Value != "":
			info.Commit = setting.Value
		case setting.Key == "vcs.time" && info.Date == defaultDate && setting.Value != "":
			info.Date = setting.Value
		}
	}
	return info
}
