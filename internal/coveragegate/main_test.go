package main

import (
	"os"
	"path/filepath"
	"testing"
)

func profile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "coverage.out")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadProfileAndValidate(t *testing.T) {
	path := profile(t, "mode: atomic\nexample/internal/crypt/a.go:1.1,1.2 85 1\nexample/internal/crypt/a.go:2.1,2.2 15 0\nexample/internal/config/a.go:1.1,1.2 100 1\nexample/internal/keys/a.go:1.1,1.2 100 1\nexample/internal/dotenv/a.go:1.1,1.2 100 1\n")
	overall, packages, err := readProfile(path)
	if err != nil {
		t.Fatal(err)
	}
	if packages["crypt"].percent() != 85 || overall.percent() != 96.25 {
		t.Fatalf("unexpected parsed percentages: crypt=%v overall=%v", packages["crypt"].percent(), overall.percent())
	}
	if err := validate(overall, packages); err != nil {
		t.Fatalf("valid profile rejected: %v", err)
	}
}

func TestCoverageGateFailures(t *testing.T) {
	for _, body := range []string{
		"",
		"not-a-header\n",
		"mode: atomic\n",
		"mode: atomic\nbad record\n",
		"mode: atomic\nexample/internal/crypt/a.go:1.1,1.2 nope 1\n",
		"mode: atomic\nno-colon 1 1\n",
	} {
		if _, _, err := readProfile(profile(t, body)); err == nil {
			t.Fatal("malformed profile accepted")
		}
	}
	if err := run(nil); err == nil {
		t.Fatal("missing command argument accepted")
	}
	low := counter{covered: 1, total: 100}
	if err := validate(low, map[string]counter{}); err == nil {
		t.Fatal("below-floor coverage accepted")
	}
}
