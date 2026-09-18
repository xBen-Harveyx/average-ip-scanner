package scan

import (
	"net"
	"testing"
)

func testRange(n int) []net.IP {
	var ips []net.IP
	for i := 1; i <= n; i++ {
		ips = append(ips, net.IPv4(10, 0, 0, byte(i)))
	}
	return ips
}

// A network where every address answers with the gateway's MAC is proxy-ARPing
// on behalf of hosts that do not exist.
func TestDetectIsolationFlagsUniformMAC(t *testing.T) {
	probe := func(net.IP) (string, bool) { return "44:12:44:c6:89:2c", true }

	got, ok := DetectIsolation(testRange(254), probe)
	if !ok {
		t.Fatal("DetectIsolation = false, want true when every address shares one MAC")
	}
	if got.MAC != "44:12:44:c6:89:2c" {
		t.Errorf("MAC = %q, want the shared MAC", got.MAC)
	}
	if len(got.Probed) != canaryCount {
		t.Errorf("probed %d addresses, want %d", len(got.Probed), canaryCount)
	}
}

// A normal subnet: most addresses are empty, so a canary goes unanswered.
func TestDetectIsolationIgnoresNormalNetwork(t *testing.T) {
	live := map[string]string{"10.0.0.1": "aa:bb:cc:00:00:01"}
	probe := func(ip net.IP) (string, bool) {
		mac, ok := live[ip.String()]
		return mac, ok
	}

	if _, ok := DetectIsolation(testRange(254), probe); ok {
		t.Error("DetectIsolation = true on a sparsely populated subnet")
	}
}

// A dense subnet of real hosts must not trip the check: real devices have
// distinct MACs even when nearly every address is occupied.
func TestDetectIsolationIgnoresDenseNetworkWithDistinctMACs(t *testing.T) {
	probe := func(ip net.IP) (string, bool) {
		return "aa:bb:cc:00:00:" + ip.String(), true
	}

	if _, ok := DetectIsolation(testRange(254), probe); ok {
		t.Error("DetectIsolation = true where every host has a distinct MAC")
	}
}

// In a tiny block there is no address that would be surprising to find live,
// so the check does not run at all.
func TestDetectIsolationSkipsSmallRanges(t *testing.T) {
	probe := func(net.IP) (string, bool) { return "44:12:44:c6:89:2c", true }

	if _, ok := DetectIsolation(testRange(6), probe); ok {
		t.Error("DetectIsolation = true on a range too small to canary")
	}
}

// A probe that claims liveness without a MAC gives nothing to compare, so the
// check must decline rather than treat empty strings as a match.
func TestDetectIsolationIgnoresEmptyMACs(t *testing.T) {
	probe := func(net.IP) (string, bool) { return "", true }

	if got, ok := DetectIsolation(testRange(254), probe); ok {
		t.Errorf("DetectIsolation = true with empty MACs (got %+v)", got)
	}
}
