package keys

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

// roundTripFunc lets a test act as an http.Client transport (a stubbed HTTP
// client) without a real network round-trip.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func stubClient(status int, body string) (*http.Client, *string) {
	var gotPath string
	c := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		gotPath = r.URL.Path
		return &http.Response{
			StatusCode: status,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
		}, nil
	})}
	return c, &gotPath
}

const (
	edKey1 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyOneExampleKeyOneExampleKeyO01"
	edKey2 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyTwoExampleKeyTwoExampleKeyT02"
	rsaKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgExampleRsaKeyExampleRsaKey user@host"
)

func TestFetchGitHubKeys(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		body     string
		wantKeys []string
		wantErr  string
	}{
		{
			name:     "ed25519 and rsa returns only ed25519",
			status:   200,
			body:     edKey1 + "\n" + rsaKey + "\n",
			wantKeys: []string{edKey1},
		},
		{
			name:     "multiple ed25519",
			status:   200,
			body:     edKey1 + "\n" + edKey2 + "\n",
			wantKeys: []string{edKey1, edKey2},
		},
		{
			name:    "only rsa is an error",
			status:  200,
			body:    rsaKey + "\n",
			wantErr: "no ssh-ed25519 keys",
		},
		{
			name:    "empty body is an error",
			status:  200,
			body:    "",
			wantErr: "no ssh-ed25519 keys",
		},
		{
			name:    "404 not found",
			status:  404,
			body:    "Not Found",
			wantErr: "not found",
		},
		{
			name:    "500 surfaces status",
			status:  500,
			body:    "oops",
			wantErr: "status 500",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, gotPath := stubClient(tt.status, tt.body)
			keys, err := fetchGitHubKeys(context.Background(), client, "octocat")

			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if strings.Join(keys, "|") != strings.Join(tt.wantKeys, "|") {
				t.Errorf("keys = %v, want %v", keys, tt.wantKeys)
			}
			if *gotPath != "/octocat.keys" {
				t.Errorf("requested path = %q, want /octocat.keys", *gotPath)
			}
		})
	}
}

func TestFetchGitHubKeysInvalidUsername(t *testing.T) {
	called := false
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		called = true
		return nil, nil
	})}
	_, err := fetchGitHubKeys(context.Background(), client, "bad user/../etc")
	if err == nil || !strings.Contains(err.Error(), "invalid GitHub username") {
		t.Fatalf("err = %v, want invalid username", err)
	}
	if called {
		t.Error("made an HTTP request for an invalid username")
	}
}
