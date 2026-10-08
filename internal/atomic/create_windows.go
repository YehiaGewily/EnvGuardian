//go:build windows

package atomic

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// maxTempAttempts bounds retries when a randomly named temp file already exists.
const maxTempAttempts = 100

// createTemp creates the temp file. When perm grants no group or other access,
// the file is created with a protected DACL that allows only the current user,
// so no byte is ever written to a file with inherited permissions. Any other
// perm uses os.CreateTemp, and the file inherits the directory's ACL.
func createTemp(dir, prefix string, perm os.FileMode) (*os.File, error) {
	if perm&0o077 != 0 {
		return os.CreateTemp(dir, prefix+"*")
	}
	return createOwnerOnlyTemp(dir, prefix, ownerOnlyDescriptor)
}

// describer returns the SID that must be a new file's only grantee and the
// security descriptor to create the file with.
type describer func() (*windows.SID, *windows.SECURITY_DESCRIPTOR, error)

// ownerOnlyDescriptor builds a protected DACL (no inherited entries) with a
// single GENERIC_ALL allow entry for the process token's user.
func ownerOnlyDescriptor() (*windows.SID, *windows.SECURITY_DESCRIPTOR, error) {
	tokenUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, nil, fmt.Errorf("resolve current user SID from process token: %w", err)
	}
	user, err := tokenUser.User.Sid.Copy()
	if err != nil {
		return nil, nil, fmt.Errorf("copy current user SID: %w", err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;" + user.String() + ")")
	if err != nil {
		return nil, nil, fmt.Errorf("build owner-only security descriptor: %w", err)
	}
	return user, sd, nil
}

// createOwnerOnlyTemp exclusively creates dir/prefix<random> with the
// descriptor from describe applied at creation, then reads the DACL back from
// the open handle. If the DACL is not exactly owner-only (for example on a
// filesystem that does not store ACLs), the empty file is removed and an error
// is returned; there is no fallback to inherited permissions.
func createOwnerOnlyTemp(dir, prefix string, describe describer) (*os.File, error) {
	user, sd, err := describe()
	if err != nil {
		return nil, ownerOnlyError(err)
	}
	sa := &windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(*sa))

	for range maxTempAttempts {
		name := filepath.Join(dir, prefix+rand.Text())
		name16, err := windows.UTF16PtrFromString(name)
		if err != nil {
			return nil, &os.PathError{Op: "open", Path: name, Err: err}
		}
		h, err := windows.CreateFile(name16,
			windows.GENERIC_READ|windows.GENERIC_WRITE,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
			sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if errors.Is(err, windows.ERROR_FILE_EXISTS) {
			continue
		}
		if err != nil {
			return nil, &os.PathError{Op: "open", Path: name, Err: err}
		}
		f := os.NewFile(uintptr(h), name)
		if err := verifyOwnerOnly(h, user); err != nil {
			_ = f.Close()
			_ = os.Remove(name)
			return nil, ownerOnlyError(err)
		}
		return f, nil
	}
	return nil, &os.PathError{Op: "createtemp", Path: filepath.Join(dir, prefix+"*"), Err: os.ErrExist}
}

func ownerOnlyError(err error) error {
	return fmt.Errorf("could not create the file with an owner-only Windows ACL, "+
		"so nothing was written (EnvGuardian never falls back to inherited permissions); "+
		"keep the repository on an NTFS or ReFS volume and run as a regular user account: %w", err)
}

// verifyOwnerOnly reads the DACL of an open file handle and checks it with
// checkOwnerOnly.
func verifyOwnerOnly(h windows.Handle, user *windows.SID) error {
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read back temp file DACL: %w", err)
	}
	return checkOwnerOnly(sd, user)
}

// checkOwnerOnly reports whether sd has a protected DACL whose only entry is a
// non-inherited allow entry for user.
func checkOwnerOnly(sd *windows.SECURITY_DESCRIPTOR, user *windows.SID) error {
	control, _, err := sd.Control()
	if err != nil {
		return fmt.Errorf("read DACL control flags: %w", err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return errors.New("temp file DACL is not protected from inheritance")
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("read temp file DACL: %w", err)
	}
	if dacl == nil {
		return errors.New("temp file has a NULL DACL, which grants everyone access")
	}
	if dacl.AceCount != 1 {
		return fmt.Errorf("temp file DACL has %d entries, want exactly 1", dacl.AceCount)
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil {
		return fmt.Errorf("read temp file DACL entry: %w", err)
	}
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags&windows.INHERITED_ACE != 0 {
		return errors.New("temp file DACL entry is not an explicit allow entry")
	}
	sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)) //nolint:gosec // G103: an ACE's SID starts at SidStart
	if !sid.Equals(user) {
		return errors.New("temp file DACL grants access to an account other than the current user")
	}
	return nil
}
