package kone

import (
	"errors"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
)

func lockFakeLedger(file *os.File) error {
	return windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &windows.Overlapped{})
}
func unlockFakeLedger(file *os.File) error {
	return windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &windows.Overlapped{})
}
func verifyFakeLedgerPath(path string, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if directory != info.IsDir() || !directory && !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("invalid Fake-IP state file type")
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	if !owner.Equals(user.User.Sid) && !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) && !owner.IsWellKnown(windows.WinLocalSystemSid) {
		return errors.New("untrusted Fake-IP state owner")
	}
	// A verified owner may have inherited a permissive ProgramData ACL. Restrict
	// this state to its owner, administrators and SYSTEM before reading bindings.
	private, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + owner.String() + ")")
	if err != nil {
		return err
	}
	dacl, _, err := private.DACL()
	if err != nil {
		return err
	}
	flags := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	var nextOwner *windows.SID
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	if member, err := windows.Token(0).IsMember(administrators); err == nil && member {
		nextOwner = administrators
		flags |= windows.OWNER_SECURITY_INFORMATION
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, flags, nextOwner, nil, dacl, nil)
}

// NTFS uses the flushed file handle for data/metadata durability. Windows does
// not support Go's directory fsync; every append still calls FlushFileBuffers.
func syncFakeLedgerDirectory(string) error     { return nil }
func fakeLedgerHostDirectory() (string, error) { return fakeLedgerRootDirectory() }
func fakeLedgerRootDirectory() (string, error) {
	path, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		return "", err
	}
	return filepath.Join(path, "KONE", "fake-ip"), nil
}

func FakeIPNeedsAuthorization() bool { return false } // Existing Windows helper selection checks elevation.
