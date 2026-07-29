package cli

import (
	"fmt"
	"os"
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
		configPath, err := filepath.Abs(flags.config)
		if err != nil {
			configPath = flags.config
		}
		configDir := filepath.Dir(configPath)
		root := configDir
		if cwd, cwdErr := os.Getwd(); cwdErr == nil {
			if gitRepo := gitOutput(cwd, "rev-parse", "--show-toplevel"); gitRepo != "" && pathWithinRoot(gitRepo, configPath) {
				root = gitRepo
			} else if strings.EqualFold(filepath.Base(configDir), config.Dir) {
				root = filepath.Dir(configDir)
			}
		} else if strings.EqualFold(filepath.Base(configDir), config.Dir) {
			root = filepath.Dir(configDir)
		}
		p := config.PathsFor(root)
		p.Config = configPath
		if base := filepath.Base(configPath); !strings.EqualFold(base, config.ConfigFile) && strings.EqualFold(filepath.Clean(configDir), filepath.Clean(p.Dir)) {
			stem := strings.TrimSuffix(base, filepath.Ext(base))
			p.Lock = filepath.Join(configDir, stem+".lock.toml")
		}
		return p
	}
	cwd, err := os.Getwd()
	if err != nil {
		return config.PathsFor(".")
	}
	if root := gitOutput(cwd, "rev-parse", "--show-toplevel"); root != "" {
		return config.PathsFor(root)
	}
	for dir := cwd; ; dir = filepath.Dir(dir) {
		if _, statErr := os.Stat(filepath.Join(dir, config.Dir, config.ConfigFile)); statErr == nil {
			if dir == cwd {
				return config.PathsFor(".")
			}
			return config.PathsFor(dir)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
	}
	return config.PathsFor(".")
}

// secureRootPaths resolves conventional metadata paths through the same
// containment boundary as configured plaintext/ciphertext mappings. This
// prevents a symlinked .envguardian directory or external --config path from
// redirecting reads or transaction writes outside the repository.
func secureRootPaths(flags *globalFlags) (config.Paths, error) {
	p := rootPaths(flags)
	rootAbs, err := filepath.Abs(p.Root)
	if err != nil {
		return config.Paths{}, withExit(exitConfig, fmt.Errorf("resolve repository root: %w", err))
	}
	rootResolved, err := filepath.EvalSymlinks(rootAbs)
	if err != nil {
		return config.Paths{}, withExit(exitConfig, fmt.Errorf("resolve repository root symlinks: %w", err))
	}
	resolve := func(label, target string) (string, error) {
		targetAbs, absErr := filepath.Abs(target)
		if absErr != nil {
			return "", fmt.Errorf("resolve %s path: %w", label, absErr)
		}
		rel, relErr := filepath.Rel(rootAbs, targetAbs)
		if relErr != nil || !pathWithinRoot(rootAbs, targetAbs) {
			return "", fmt.Errorf("%s path %s is outside the repository", label, target)
		}
		resolved, resolveErr := config.ResolveManagedPath(rootResolved, filepath.ToSlash(rel))
		if resolveErr != nil {
			return "", fmt.Errorf("unsafe %s path %s: %w", label, target, resolveErr)
		}
		return resolved, nil
	}
	p.Root = rootResolved
	if p.Config, err = resolve("config", p.Config); err != nil {
		return config.Paths{}, withExit(exitConfig, err)
	}
	if p.Recipients, err = resolve("recipients", p.Recipients); err != nil {
		return config.Paths{}, withExit(exitConfig, err)
	}
	if p.Lock, err = resolve("lock", p.Lock); err != nil {
		return config.Paths{}, withExit(exitConfig, err)
	}
	if p.State, err = resolve("automatic-decryption state", p.State); err != nil {
		return config.Paths{}, withExit(exitConfig, err)
	}
	p.Dir = filepath.Dir(p.Recipients)
	return p, nil
}

func pathWithinRoot(root, target string) bool {
	rel, err := filepath.Rel(root, target)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
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

// display renders a path relative to the current directory when possible and
// uses forward slashes so output is stable across operating systems.
func display(path string) string {
	cwd, cwdErr := os.Getwd()
	abs, absErr := filepath.Abs(path)
	if cwdErr == nil {
		if resolved, err := filepath.EvalSymlinks(cwd); err == nil {
			cwd = resolved
		}
	}
	if cwdErr == nil && absErr == nil && pathWithinRoot(cwd, abs) {
		if rel, err := filepath.Rel(cwd, abs); err == nil {
			return filepath.ToSlash(rel)
		}
	}
	return filepath.ToSlash(path)
}
