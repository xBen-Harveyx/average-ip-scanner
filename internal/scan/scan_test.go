package scan

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestScanCollectsAliveHostsSorted(t *testing.T) {
	ips := []net.IP{
		net.ParseIP("192.168.1.10"),
		net.ParseIP("192.168.1.2"),
		net.ParseIP("192.168.1.5"),
		net.ParseIP("192.168.1.20"),
	}

	// Only .2 and .10 answer ARP.
	macs := map[string]string{
		"192.168.1.2":  "aa:bb:cc:00:00:02",
		"192.168.1.10": "aa:bb:cc:00:00:10",
	}

	opts := Options{
		Workers:          4,
		ProgressInterval: time.Hour, // effectively disable periodic ticks
		Resolve:          true,
		ProgressOut:      io.Discard,
		Probe: func(ip net.IP) (string, bool) {
			mac, ok := macs[ip.String()]
			return mac, ok
		},
		ResolveHost:  func(_ context.Context, ip string) string { return "host-" + ip },
		LookupVendor: func(mac string) string { return "TestVendor" },
	}

	hosts := Scan(context.Background(), ips, opts)

	if len(hosts) != 2 {
		t.Fatalf("got %d hosts, want 2", len(hosts))
	}
	// Sorted numerically: .2 before .10.
	if hosts[0].IP != "192.168.1.2" || hosts[1].IP != "192.168.1.10" {
		t.Fatalf("unexpected order: %s, %s", hosts[0].IP, hosts[1].IP)
	}
	if hosts[0].MAC != "aa:bb:cc:00:00:02" {
		t.Errorf("MAC = %s, want aa:bb:cc:00:00:02", hosts[0].MAC)
	}
	if hosts[0].Hostname != "host-192.168.1.2" {
		t.Errorf("Hostname = %s, want host-192.168.1.2", hosts[0].Hostname)
	}
	if hosts[0].Manufacturer != "TestVendor" {
		t.Errorf("Manufacturer = %s, want TestVendor", hosts[0].Manufacturer)
	}
}

func TestScanNoResolveLeavesHostnameEmpty(t *testing.T) {
	opts := Options{
		Workers:          2,
		ProgressInterval: time.Hour,
		Resolve:          false,
		ProgressOut:      io.Discard,
		Probe:            func(net.IP) (string, bool) { return "aa:bb:cc:dd:ee:ff", true },
		ResolveHost:      func(context.Context, string) string { return "should-not-be-called" },
	}

	hosts := Scan(context.Background(), []net.IP{net.ParseIP("10.0.0.1")}, opts)
	if len(hosts) != 1 {
		t.Fatalf("got %d hosts, want 1", len(hosts))
	}
	if hosts[0].Hostname != "" {
		t.Errorf("Hostname = %q, want empty", hosts[0].Hostname)
	}
}
