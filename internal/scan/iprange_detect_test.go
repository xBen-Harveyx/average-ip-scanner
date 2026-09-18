package scan

import (
	"net"
	"testing"
)

// On a machine with a default route, auto-detect must come from that route
// rather than from whichever private interface happens to be enumerated first.
func TestDetectLocalSubnetPrefersDefaultRoute(t *testing.T) {
	routed, err := defaultRouteSubnet()
	if err != nil {
		t.Skipf("no usable default route in this environment: %v", err)
	}

	if _, _, err := net.ParseCIDR(routed); err != nil {
		t.Fatalf("defaultRouteSubnet returned %q, which is not a CIDR: %v", routed, err)
	}

	got, err := DetectLocalSubnet()
	if err != nil {
		t.Fatalf("DetectLocalSubnet: %v", err)
	}
	if got != routed {
		t.Errorf("DetectLocalSubnet = %q, want the default-route subnet %q", got, routed)
	}
	t.Logf("default route subnet = %s", routed)
}
