//go:build windows

package intentcarrier

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func acquireStoreLock(directory string) (*os.File, error) {
	path := filepath.Join(directory, ".carrier.lock")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	overlapped := new(windows.Overlapped)
	if err := windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, overlapped); err != nil {
		_ = file.Close()
		return nil, errors.New("Intent Carrier directory is already owned by another process")
	}
	return file, nil
}

func releaseStoreLock(file *os.File) error {
	overlapped := new(windows.Overlapped)
	unlockErr := windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, overlapped)
	closeErr := file.Close()
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}
