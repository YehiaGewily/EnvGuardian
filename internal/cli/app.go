package cli

import (
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/YehiaGewily/envguardian/internal/config"
	"github.com/YehiaGewily/envguardian/internal/keys"
)

// nowDate returns today's date. It is a var so golden tests can pin it.
var nowDate = func() string { return time.Now().UTC().Format("2006-01-02") }

// rootPaths resolves the .envguardian paths, honoring --config if set.
func rootPaths(flags *globalFlags) config.Paths {
	if flags.config != "" {
		root := filepath.Dir(filepath.Dir(flags.config)) // <root>/.envguardian/config.toml
		p := config.PathsFor(root)
		p.Config = flags.config
		return p
	}
	return config.PathsFor(".")
}

// currentUser returns a bare username for recipient metadata.
func currentUser() string {
	u, err := user.Current()
	if err != nil || u.Username == "" {
		return "me"
	}
	name := u.Username
	if i := strings.LastIndexAny(name, `\/`); i >= 0 {
		name = name[i+1:]
	}
	return name
}

func loadConfig(p config.Paths) (*config.Config, error) {
	c, err := config.Load(p.Root, p.Config)
	if err != nil {
		return nil, withExit(exitConfig, err)
	}
	return c, nil
}

func loadRecipients(p config.Paths) (*keys.RecipientsFile, error) {
	rf, err := keys.LoadRecipients(p.Recipients)
	if err != nil {
		return nil, withExit(exitConfig, err)
	}
	return rf, nil
}

// display renders a path with forward slashes so output is stable across OSes.
func display(path string) string { return filepath.ToSlash(path) }
