package syncplan

import "os"

// stagedTarget owns a private, not-yet-committed file and the directory
// authority needed for an atomic no-overwrite commit. Always call cleanup.
// file may already be closed by copyOneAtomic when cleanup runs.
type stagedTarget struct {
	file    *os.File
	commit  func() (bool, error)
	cleanup func()
}
