//go:build !windows

package trustedcapabilitycarrier

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

func acquireStoreLock(directory string) (*os.File, error) {
	file, err := os.OpenFile(filepath.Join(directory, ".capability-carrier.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, errors.New("capability Carrier directory is already fenced by another writer")
	}
	return file, nil
}

func releaseStoreLock(file *os.File) error {
	unlockErr := syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	closeErr := file.Close()
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}
