//go:build windows

package quotesource

import "os"

// The production Windows installer must enforce an owner-only DACL. Go's
// portable FileInfo does not expose the owning SID; reparse points remain
// rejected by the regular-file and SameFile checks in readPrivate.
func fileOwner(info os.FileInfo) bool {
	return info != nil && info.Mode()&os.ModeSymlink == 0
}
