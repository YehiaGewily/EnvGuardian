//go:build windows

package atomic

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// sentinel stands in for a secret value. It must never appear in an error.
const sentinel = "ENVGUARDIAN_SENTINEL_ACL_7c41d9"

const (
	authenticatedUsersSID = "S-1-5-11"
	builtinUsersSID       = "S-1-5-32-545"
)

type aceInfo struct {
	allow     bool
	inherited bool
	sid       string
}

func currentUserSID(t *testing.T) *windows.SID {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatalf("token user: %v", err)
	}
	sid, err := user.User.Sid.Copy()
	if err != nil {
		t.Fatal(err)
	}
	return sid
}

// looseDir returns a temp directory whose DACL lets Authenticated Users modify
// and Users read every file created inside it, like a non-profile drive root.
func looseDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	user := currentUserSID(t).String()
	sd, err := windows.SecurityDescriptorFromString("D:P" +
		"(A;OICI;FA;;;" + user + ")" +
		"(A;OICI;0x1301bf;;;" + authenticatedUsersSID + ")" +
		"(A;OICI;0x1200a9;;;" + builtinUsersSID + ")")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		t.Fatalf("loosen directory DACL: %v", err)
	}
	return dir
}

// readDACL reads path's DACL by name and lists its entries.
func readDACL(t *testing.T, path string) (protected bool, aces []aceInfo) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("GetNamedSecurityInfo: %v", err)
	}
	control, _, err := sd.Control()
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if dacl == nil {
		t.Fatal("NULL DACL")
	}
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatal(err)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		aces = append(aces, aceInfo{
			allow:     ace.Header.AceType == windows.ACCESS_ALLOWED_ACE_TYPE,
			inherited: ace.Header.AceFlags&windows.INHERITED_ACE != 0,
			sid:       sid.String(),
		})
	}
	return control&windows.SE_DACL_PROTECTED != 0, aces
}

func assertOwnerOnly(t *testing.T, path string) {
	t.Helper()
	user := currentUserSID(t).String()
	protected, aces := readDACL(t, path)
	if !protected {
		t.Error("DACL is not protected")
	}
	allows := 0
	for _, ace := range aces {
		if ace.inherited {
			t.Errorf("inherited ACE present: %+v", ace)
		}
		if ace.allow {
			allows++
			if ace.sid != user {
				t.Errorf("allow ACE for %s, want only %s", ace.sid, user)
			}
		}
	}
	if allows != 1 || len(aces) != 1 {
		t.Errorf("DACL = %+v, want exactly one allow ACE for %s", aces, user)
	}
}

func hasInheritedAllow(aces []aceInfo, sid string) bool {
	for _, ace := range aces {
		if ace.allow && ace.inherited && ace.sid == sid {
			return true
		}
	}
	return false
}

func assertContent(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Error("file content does not match what was written")
	}
}

func assertNoSentinel(t *testing.T, err error) {
	t.Helper()
	if err != nil && strings.Contains(err.Error(), sentinel) {
		t.Error("error message contains the secret sentinel")
	}
}

func TestOwnerOnlyWriteHasProtectedDACL(t *testing.T) {
	t.Run("new file", func(t *testing.T) {
		dir := looseDir(t)
		path := filepath.Join(dir, ".env")
		err := WriteFile(path, []byte(sentinel), 0o600)
		assertNoSentinel(t, err)
		if err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		assertOwnerOnly(t, path)
		assertContent(t, path, []byte(sentinel))
		if leftovers := tempFiles(t, dir); len(leftovers) != 0 {
			t.Errorf("temp files left behind: %v", leftovers)
		}
	})

	t.Run("replaces loose file", func(t *testing.T) {
		dir := looseDir(t)
		path := filepath.Join(dir, ".env")
		if err := os.WriteFile(path, []byte("OLD=1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		// Prove the precondition: the existing file is readable by others.
		if protected, aces := readDACL(t, path); protected || !hasInheritedAllow(aces, builtinUsersSID) {
			t.Fatalf("setup: existing file DACL is not loose: protected=%v aces=%+v", protected, aces)
		}
		err := WriteFile(path, []byte(sentinel), 0o600)
		assertNoSentinel(t, err)
		if err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		assertOwnerOnly(t, path)
		assertContent(t, path, []byte(sentinel))
	})
}

func TestSharedWriteInheritsDirectoryDACL(t *testing.T) {
	dir := looseDir(t)
	path := filepath.Join(dir, "config.toml")
	if err := WriteFile(path, []byte("x = 1\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	protected, aces := readDACL(t, path)
	if protected {
		t.Error("0644 write produced a protected DACL; want inherited permissions")
	}
	for _, sid := range []string{authenticatedUsersSID, builtinUsersSID} {
		if !hasInheritedAllow(aces, sid) {
			t.Errorf("missing inherited allow ACE for %s: %+v", sid, aces)
		}
	}
}

func TestOwnerOnlyFailsClosed(t *testing.T) {
	user := currentUserSID(t)
	descriptor := func(sddl string) describer {
		return func() (*windows.SID, *windows.SECURITY_DESCRIPTOR, error) {
			sd, err := windows.SecurityDescriptorFromString(sddl)
			if err != nil {
				t.Fatal(err)
			}
			return user, sd, nil
		}
	}
	errSID := errors.New("token unavailable")
	cases := []struct {
		name     string
		describe describer
		want     error
	}{
		{"user SID unresolvable", func() (*windows.SID, *windows.SECURITY_DESCRIPTOR, error) {
			return nil, nil, errSID
		}, errSID},
		{"DACL omits current user", descriptor("D:P(A;;GA;;;SY)"), nil},
		{"DACL grants everyone", descriptor("D:P(A;;GA;;;" + user.String() + ")(A;;GR;;;WD)"), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := looseDir(t)
			path := filepath.Join(dir, ".env")
			if err := os.WriteFile(path, []byte("KEEP=1\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			create := func(dir, prefix string, _ os.FileMode) (*os.File, error) {
				return createOwnerOnlyTemp(dir, prefix, tc.describe)
			}
			err := writeFile(path, []byte(sentinel), 0o600, create)
			if err == nil {
				t.Fatal("writeFile succeeded without an owner-only DACL")
			}
			assertNoSentinel(t, err)
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Errorf("error does not wrap the cause: %v", err)
			}
			if leftovers := tempFiles(t, dir); len(leftovers) != 0 {
				t.Errorf("temp files left behind: %v", leftovers)
			}
			assertContent(t, path, []byte("KEEP=1\n"))
		})
	}
}

func TestOwnerOnlyCreateMissingDirIsNotExist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", ".env")
	err := WriteFile(path, []byte(sentinel), 0o600)
	assertNoSentinel(t, err)
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("error = %v, want fs.ErrNotExist", err)
	}
}

func TestCheckOwnerOnly(t *testing.T) {
	user := currentUserSID(t)
	u := user.String()
	cases := []struct {
		name string
		sddl string
		ok   bool
	}{
		{"protected owner only", "D:P(A;;FA;;;" + u + ")", true},
		{"not protected", "D:(A;;FA;;;" + u + ")", false},
		{"null DACL", "D:NO_ACCESS_CONTROL", false},
		{"empty DACL", "D:P", false},
		{"extra entry", "D:P(A;;FA;;;" + u + ")(A;;FR;;;BU)", false},
		{"other account", "D:P(A;;FA;;;BU)", false},
		{"deny entry", "D:P(D;;FA;;;" + u + ")", false},
		{"inherited entry", "D:P(A;ID;FA;;;" + u + ")", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString(tc.sddl)
			if err != nil {
				t.Fatal(err)
			}
			err = checkOwnerOnly(sd, user)
			if (err == nil) != tc.ok {
				t.Errorf("checkOwnerOnly(%s) = %v, want ok=%v", tc.sddl, err, tc.ok)
			}
		})
	}
}
