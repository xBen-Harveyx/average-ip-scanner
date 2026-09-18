package scan

import "testing"

func TestExpandCIDR(t *testing.T) {
	tests := []struct {
		name      string
		cidr      string
		wantFirst string
		wantLast  string
		wantCount int
	}{
		{"slash24 skips network and broadcast", "192.168.1.0/24", "192.168.1.1", "192.168.1.254", 254},
		{"slash30 has two usable hosts", "10.0.0.0/30", "10.0.0.1", "10.0.0.2", 2},
		{"slash31 point-to-point keeps both", "10.0.0.0/31", "10.0.0.0", "10.0.0.1", 2},
		{"slash32 single host", "10.0.0.5/32", "10.0.0.5", "10.0.0.5", 1},
		{"non-zero base is masked to network", "192.168.1.37/24", "192.168.1.1", "192.168.1.254", 254},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ips, err := ExpandCIDR(tt.cidr)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(ips) != tt.wantCount {
				t.Fatalf("count = %d, want %d", len(ips), tt.wantCount)
			}
			if got := ips[0].String(); got != tt.wantFirst {
				t.Errorf("first = %s, want %s", got, tt.wantFirst)
			}
			if got := ips[len(ips)-1].String(); got != tt.wantLast {
				t.Errorf("last = %s, want %s", got, tt.wantLast)
			}
		})
	}
}

func TestExpandCIDRErrors(t *testing.T) {
	for _, cidr := range []string{"not-a-cidr", "192.168.1.0", "2001:db8::/64", "10.0.0.0/8"} {
		if _, err := ExpandCIDR(cidr); err == nil {
			t.Errorf("ExpandCIDR(%q) = nil error, want error", cidr)
		}
	}
}

// The guard is a ceiling, not a fence: a /16 sits exactly at the limit and must
// be allowed, while anything larger is refused.
func TestExpandCIDRLimitBoundary(t *testing.T) {
	ips, err := ExpandCIDR("10.0.0.0/16")
	if err != nil {
		t.Fatalf("a /16 sits at the limit and should be allowed: %v", err)
	}
	if want := 65534; len(ips) != want {
		t.Errorf("a /16 yielded %d usable hosts, want %d", len(ips), want)
	}

	if _, err := ExpandCIDR("10.0.0.0/15"); err == nil {
		t.Error("a /15 exceeds the limit and should be refused")
	}
}
