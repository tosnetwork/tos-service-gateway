//go:build windows

package trustedcapabilitycarrier

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func acquireStoreLock(directory string) (*os.File, error) {
	file, err := os.OpenFile(filepath.Join(directory, ".capability-carrier.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, new(windows.Overlapped)); err != nil {
		_ = file.Close()
		return nil, errors.New("capability Carrier directory is already fenced by another writer")
	}
	return file, nil
}

func releaseStoreLock(file *os.File) error {
	unlockErr := windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, new(windows.Overlapped))
	closeErr := file.Close()
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}
