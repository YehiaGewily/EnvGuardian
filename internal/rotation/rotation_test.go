package rotation

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestLedgerAddDoneAndRoundTrip(t *testing.T) {
	ledger := New()
	if err := ledger.AddKeys([]string{"TOKEN", "DATABASE_URL", "TOKEN"}); err != nil {
		t.Fatal(err)
	}
	if got, want := ledger.Keys(), []string{"DATABASE_URL", "TOKEN"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("keys = %v, want %v", got, want)
	}
	data, err := ledger.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.Done("TOKEN") || parsed.Done("NOT_PENDING") {
		t.Fatal("Done did not report exact pending-key membership")
	}
	if got := parsed.Keys(); !reflect.DeepEqual(got, []string{"DATABASE_URL"}) {
		t.Fatalf("remaining keys = %v", got)
	}
}

func TestParseFailsClosed(t *testing.T) {
	tests := []struct{ name, body, want string }{
		{name: "malformed", body: "version = [", want: "malformed TOML"},
		{name: "unsupported", body: "version = 2\n", want: "unsupported version"},
		{name: "unknown", body: "version = 1\nsecret = true\n", want: "unknown field"},
		{name: "empty key", body: "version = 1\n[[pending]]\nkey = \" \"\n", want: "empty key"},
		{name: "duplicate", body: "version = 1\n[[pending]]\nkey = \"TOKEN\"\n[[pending]]\nkey = \"TOKEN\"\n", want: "duplicate"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.body))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestLoadMissingIsEmptyButOtherReadErrorsFail(t *testing.T) {
	dir := t.TempDir()
	ledger, err := Load(filepath.Join(dir, "missing.toml"))
	if err != nil || len(ledger.Pending) != 0 {
		t.Fatalf("missing ledger = %+v, %v", ledger, err)
	}
	_, err = Load(dir)
	if err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatalf("directory read error = %v", err)
	}
}

func TestSaveUsesPublicMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows permission bits do not represent the destination ACL")
	}
	path := filepath.Join(t.TempDir(), FileName)
	ledger := New()
	if err := ledger.AddKeys([]string{"TOKEN"}); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Save(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 && info.Mode().Perm() != 0o644 {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}
}

func TestLedgerMutationValidationFailures(t *testing.T) {
	ledger := &Ledger{}
	if err := ledger.AddKeys([]string{"TOKEN"}); err != nil || ledger.Version != Version {
		t.Fatalf("zero-version AddKeys = %+v, %v", ledger, err)
	}
	if err := ledger.AddKeys([]string{"bad\nkey"}); err == nil {
		t.Fatal("invalid key name was accepted")
	}
	ledger.Version = 99
	if _, err := ledger.Marshal(); err == nil {
		t.Fatal("unsupported version was marshaled")
	}
}
