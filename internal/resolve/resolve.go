// Package resolve performs best-effort reverse-DNS hostname lookups.
package resolve

import (
	"context"
	"net"
	"strings"
	"time"
)

// Lookup returns the first reverse-DNS name for ip with the trailing dot
// removed, or "" if none is found. It is best-effort and never fails hard: a
// missing PTR record is the common case on a LAN, not an error.
func Lookup(ctx context.Context, ip string) string {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}
