package scan

import (
	"io"
	"net"
	"os"
	"testing"
)

func TestCompareIP(t *testing.T) {
	tests := []struct {
		name string
		a, b string
		want int // -1 a first, 0 equal, 1 b first
	}{
		{"numeric not lexical", "192.168.1.2", "192.168.1.10", -1},
		{"equal", "10.0.0.1", "10.0.0.1", 0},
		{"higher octet wins", "10.0.2.1", "10.0.1.99", 1},
		{"first octet dominates", "9.255.255.255", "10.0.0.0", -1},
		{"unparseable sorts last", "not-an-ip", "10.0.0.1", 1},
		{"unparseable sorts last, reversed", "10.0.0.1", "not-an-ip", -1},
		{"two unparseable are equal", "nope", "also-nope", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := compareIP(tt.a, tt.b)
			switch {
			case tt.want < 0 && got >= 0:
				t.Errorf("compareIP(%q, %q) = %d, want negative", tt.a, tt.b, got)
			case tt.want > 0 && got <= 0:
				t.Errorf("compareIP(%q, %q) = %d, want positive", tt.a, tt.b, got)
			case tt.want == 0 && got != 0:
				t.Errorf("compareIP(%q, %q) = %d, want 0", tt.a, tt.b, got)
			}
		})
	}
}

// An IPv6 address has no To4 form, so it must sort with the unparseable ones
// rather than panicking.
func TestCompareIPHandlesIPv6(t *testing.T) {
	if got := compareIP("2001:db8::1", "10.0.0.1"); got <= 0 {
		t.Errorf("compareIP(ipv6, ipv4) = %d, want the IPv6 address to sort last", got)
	}
}

func TestWithDefaults(t *testing.T) {
	// Zero workers would consume no jobs and silently return nothing.
	if got := withDefaults(Options{}); got.Workers < 1 {
		t.Errorf("Workers = %d, want at least 1", got.Workers)
	}
	// An explicit count is left alone; the user-facing default lives in config.
	if got := withDefaults(Options{Workers: 7}); got.Workers != 7 {
		t.Errorf("Workers = %d, want the caller's 7", got.Workers)
	}
	if got := withDefaults(Options{}); got.Probe == nil {
		t.Error("Probe = nil, want the real ARP probe as the fallback")
	}
	if got := withDefaults(Options{}); got.ProgressOut != os.Stderr {
		t.Error("ProgressOut should default to stderr")
	}
	// Progress is opt-out, so a zero interval must survive withDefaults.
	if got := withDefaults(Options{ProgressInterval: 0}); got.ProgressInterval != 0 {
		t.Errorf("ProgressInterval = %v, want 0 to stay disabled", got.ProgressInterval)
	}
	// An injected writer is not replaced.
	if got := withDefaults(Options{ProgressOut: io.Discard}); got.ProgressOut != io.Discard {
		t.Error("an injected ProgressOut should be left alone")
	}
}

func TestFirstPrivateSubnet(t *testing.T) {
	got, err := firstPrivateSubnet()
	if err != nil {
		t.Skipf("no private interface in this environment: %v", err)
	}

	ip, ipNet, err := net.ParseCIDR(got)
	if err != nil {
		t.Fatalf("firstPrivateSubnet returned %q, which is not a CIDR: %v", got, err)
	}
	if !ip.IsPrivate() {
		t.Errorf("firstPrivateSubnet returned %q, which is not a private range", got)
	}
	// The result must be the network address, not a host address on it.
	if !ipNet.IP.Equal(ip) {
		t.Errorf("firstPrivateSubnet returned %q, want the network address", got)
	}
}

func TestSubnetContainingRejectsForeignIP(t *testing.T) {
	// An address no local interface holds has no subnet to report.
	if got, err := subnetContaining(net.IPv4(203, 0, 113, 7)); err == nil {
		t.Errorf("subnetContaining(203.0.113.7) = %q, want an error", got)
	}
}
