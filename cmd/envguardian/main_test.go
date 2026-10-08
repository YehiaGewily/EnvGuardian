package main

import (
	"runtime/debug"
	"testing"

	"github.com/YehiaGewily/envguardian/internal/cli"
)

func TestResolveBuildInfo(t *testing.T) {
	vcs := []debug.BuildSetting{
		{Key: "vcs", Value: "git"},
		{Key: "vcs.revision", Value: "0123456789abcdef0123456789abcdef01234567"},
		{Key: "vcs.time", Value: "2026-08-01T12:00:00Z"},
	}
	tests := []struct {
		name                  string
		version, commit, date string
		embedded              *debug.BuildInfo
		want                  cli.BuildInfo
	}{
		{
			name:    "no embedded build info keeps defaults",
			version: defaultVersion, commit: defaultCommit, date: defaultDate,
			want: cli.BuildInfo{Version: "dev", Commit: "none", Date: "unknown"},
		},
		{
			name:    "go install of a tagged module reports the module version",
			version: defaultVersion, commit: defaultCommit, date: defaultDate,
			embedded: &debug.BuildInfo{Main: debug.Module{Version: "v0.2.1"}},
			want:     cli.BuildInfo{Version: "v0.2.1", Commit: "none", Date: "unknown"},
		},
		{
			name:    "build from a checkout reports VCS revision and time",
			version: defaultVersion, commit: defaultCommit, date: defaultDate,
			embedded: &debug.BuildInfo{Main: debug.Module{Version: "v0.2.2-0.20260801120000-0123456789ab"}, Settings: vcs},
			want: cli.BuildInfo{
				Version: "v0.2.2-0.20260801120000-0123456789ab",
				Commit:  "0123456789abcdef0123456789abcdef01234567",
				Date:    "2026-08-01T12:00:00Z",
			},
		},
		{
			name:    "a (devel) module version is not reported",
			version: defaultVersion, commit: defaultCommit, date: defaultDate,
			embedded: &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}},
			want:     cli.BuildInfo{Version: "dev", Commit: "none", Date: "unknown"},
		},
		{
			name:    "ldflags values win over embedded build info",
			version: "v0.2.1", commit: "abc1234", date: "2026-08-01T00:00:00Z",
			embedded: &debug.BuildInfo{Main: debug.Module{Version: "v9.9.9"}, Settings: vcs},
			want:     cli.BuildInfo{Version: "v0.2.1", Commit: "abc1234", Date: "2026-08-01T00:00:00Z"},
		},
		{
			name:    "only fields left at their defaults fall back",
			version: "v0.2.1", commit: defaultCommit, date: defaultDate,
			embedded: &debug.BuildInfo{Main: debug.Module{Version: "v9.9.9"}, Settings: vcs},
			want:     cli.BuildInfo{Version: "v0.2.1", Commit: "0123456789abcdef0123456789abcdef01234567", Date: "2026-08-01T12:00:00Z"},
		},
		{
			name:    "empty VCS values do not replace defaults",
			version: defaultVersion, commit: defaultCommit, date: defaultDate,
			embedded: &debug.BuildInfo{Settings: []debug.BuildSetting{{Key: "vcs.revision"}, {Key: "vcs.time"}}},
			want:     cli.BuildInfo{Version: "dev", Commit: "none", Date: "unknown"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveBuildInfo(tt.version, tt.commit, tt.date, tt.embedded); got != tt.want {
				t.Errorf("resolveBuildInfo() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
