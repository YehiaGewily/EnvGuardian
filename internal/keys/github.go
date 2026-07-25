package keys

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

// githubBaseURL is a var (not const) so tests can point it at a stub server.
var githubBaseURL = "https://github.com"

// defaultHTTPClient is used by FetchGitHubKeys; tests call fetchGitHubKeys with
// their own client.
var defaultHTTPClient = &http.Client{}

// maxKeysResponse caps how much of the .keys response we read.
const maxKeysResponse = 1 << 20 // 1 MiB

var githubUsername = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$`)

// FetchGitHubKeys fetches https://github.com/<username>.keys and returns every
// ssh-ed25519 public key found. It errors clearly if the user has none.
func FetchGitHubKeys(ctx context.Context, username string) ([]string, error) {
	return fetchGitHubKeys(ctx, defaultHTTPClient, username)
}

func fetchGitHubKeys(ctx context.Context, client *http.Client, username string) ([]string, error) {
	if !githubUsername.MatchString(username) {
		return nil, fmt.Errorf("invalid GitHub username %q: expected letters, digits, and hyphens", username)
	}

	url := githubBaseURL + "/" + username + ".keys"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request for %s: %w", url, err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("GitHub user %q not found (404 from %s)", username, url)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: GitHub returned status %d", url, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxKeysResponse))
	if err != nil {
		return nil, fmt.Errorf("read keys for %q: %w", username, err)
	}

	var ed25519Keys []string
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ssh-ed25519") {
			ed25519Keys = append(ed25519Keys, line)
		}
	}

	if len(ed25519Keys) == 0 {
		return nil, fmt.Errorf(
			"no ssh-ed25519 keys found for GitHub user %q: they may have only RSA keys or none — "+
				"ask them to add an Ed25519 key (ssh-keygen -t ed25519) or supply the key with --key/--ssh",
			username)
	}
	return ed25519Keys, nil
}
