//go:build !windows

package quotesource

import (
	"os"
	"syscall"
)

func fileOwner(info os.FileInfo) bool {
	if info == nil {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}
