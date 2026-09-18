package scan

import (
	"context"
	"io"
	"net"
	"strings"
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

	hosts, probed := Scan(context.Background(), ips, opts)

	if len(hosts) != 2 {
		t.Fatalf("got %d hosts, want 2", len(hosts))
	}
	if probed != len(ips) {
		t.Errorf("probed = %d, want %d (a full sweep)", probed, len(ips))
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

	hosts, _ := Scan(context.Background(), []net.IP{net.ParseIP("10.0.0.1")}, opts)
	if len(hosts) != 1 {
		t.Fatalf("got %d hosts, want 1", len(hosts))
	}
	if hosts[0].Hostname != "" {
		t.Errorf("Hostname = %q, want empty", hosts[0].Hostname)
	}
}

// A cancelled scan must report how far it actually got, so callers can tell a
// partial host list from a complete one.
func TestScanReportsPartialProbeCountOnCancel(t *testing.T) {
	var ips []net.IP
	for i := 1; i <= 50; i++ {
		ips = append(ips, net.IPv4(10, 0, 0, byte(i)))
	}

	ctx, cancel := context.WithCancel(context.Background())
	var calls int

	opts := Options{
		Workers:          1, // single worker keeps the cancel point deterministic
		ProgressInterval: time.Hour,
		ProgressOut:      io.Discard,
		Probe: func(net.IP) (string, bool) {
			calls++
			if calls == 3 {
				cancel()
			}
			return "", false
		},
	}

	hosts, probed := Scan(ctx, ips, opts)
	defer cancel()

	if len(hosts) != 0 {
		t.Errorf("got %d hosts, want 0 (no probe succeeded)", len(hosts))
	}
	if probed == 0 || probed >= len(ips) {
		t.Errorf("probed = %d, want a partial count between 1 and %d", probed, len(ips)-1)
	}
}

// Ports that were never probed must stay flagged as unscanned, so an empty
// OpenPorts is not read as "nothing open".
func TestScanRecordsPortScanCompletion(t *testing.T) {
	opts := Options{
		Workers:          1,
		ProgressInterval: time.Hour,
		ProgressOut:      io.Discard,
		Probe:            func(net.IP) (string, bool) { return "aa:bb:cc:dd:ee:ff", true },
		ScanPorts:        func(context.Context, string) ([]int, bool) { return nil, false },
	}

	hosts, _ := Scan(context.Background(), []net.IP{net.ParseIP("10.0.0.1")}, opts)
	if len(hosts) != 1 {
		t.Fatalf("got %d hosts, want 1", len(hosts))
	}
	if hosts[0].PortsScanned {
		t.Error("PortsScanned = true, want false when the port probe did not complete")
	}

	opts.ScanPorts = func(context.Context, string) ([]int, bool) { return []int{80}, true }
	hosts, _ = Scan(context.Background(), []net.IP{net.ParseIP("10.0.0.1")}, opts)
	if !hosts[0].PortsScanned {
		t.Error("PortsScanned = false, want true when the port probe completed")
	}
}

// With no ScanPorts injected, port scanning is disabled and must not be
// reported as a completed scan that found nothing.
func TestScanLeavesPortsUnscannedWhenDisabled(t *testing.T) {
	opts := Options{
		Workers:          1,
		ProgressInterval: time.Hour,
		ProgressOut:      io.Discard,
		Probe:            func(net.IP) (string, bool) { return "aa:bb:cc:dd:ee:ff", true },
	}

	hosts, _ := Scan(context.Background(), []net.IP{net.ParseIP("10.0.0.1")}, opts)
	if hosts[0].PortsScanned {
		t.Error("PortsScanned = true, want false when port scanning is disabled")
	}
}

// Progress output is opt-out: a zero interval must write nothing at all.
func TestScanProgressDisabledWritesNothing(t *testing.T) {
	var progress strings.Builder

	opts := Options{
		Workers:          2,
		ProgressInterval: 0, // disabled
		ProgressOut:      &progress,
		Probe:            func(net.IP) (string, bool) { return "aa:bb:cc:dd:ee:ff", true },
	}

	hosts, _ := Scan(context.Background(), testRange(4), opts)
	if len(hosts) != 4 {
		t.Fatalf("got %d hosts, want 4", len(hosts))
	}
	if progress.String() != "" {
		t.Errorf("progress output written despite being disabled: %q", progress.String())
	}
}
