//go:build !windows

package scan

import "net"

// arpProbe is a no-op on non-Windows platforms; the tool is Windows-only, but
// the stub lets the module build and its tests run anywhere.
func arpProbe(net.IP) (string, bool) {
	return "", false
}
