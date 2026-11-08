//go:build !linux && !android && !darwin && !freebsd && !openbsd && !netbsd

package syncplan

import "errors"

// Fail closed rather than run without a reliable interprocess lock.
func lockDurableState(string) (func(), error) {
	return nil, errors.New("durable sync requires Unix flock support on this operating system")
}
