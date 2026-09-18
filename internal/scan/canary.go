package scan

import (
	"math/rand"
	"net"
	"sync"
)

const (
	// canaryCount is how many unlikely addresses to probe before a real scan.
	canaryCount = 3
	// minCanaryRange is the smallest range worth canarying. In a very small
	// block there is no address that would be surprising to find occupied.
	minCanaryRange = 16
)

// Isolation describes a network that answers ARP for addresses that are not
// really there, which is what guest SSIDs and client-isolated wireless do:
// the gateway proxy-ARPs everything so clients cannot reach each other. On such
// a network every address "responds", and a scan of it is pure fabrication.
type Isolation struct {
	MAC    string   // the MAC every probed address answered with
	Probed []net.IP // the canary addresses that were tried
}

// DetectIsolation probes a few randomly chosen addresses that are unlikely to
// all be occupied. If every one of them answers with the same MAC, the network
// is answering on behalf of addresses that do not exist.
//
// Requiring a shared MAC is what keeps a densely populated subnet from tripping
// the check: real hosts have distinct MACs, a proxy has one. The probes run
// concurrently so the check costs one ARP timeout rather than canaryCount of
// them, since an unanswered probe is the common (healthy) case.
func DetectIsolation(ips []net.IP, probe func(net.IP) (string, bool)) (Isolation, bool) {
	if len(ips) < minCanaryRange {
		return Isolation{}, false
	}
	if probe == nil {
		probe = arpProbe
	}

	picks := rand.Perm(len(ips))[:canaryCount]
	macs := make([]string, len(picks))
	probed := make([]net.IP, len(picks))

	var wg sync.WaitGroup
	for i, pick := range picks {
		wg.Add(1)
		go func(slot int, ip net.IP) {
			defer wg.Done()
			probed[slot] = ip
			if mac, alive := probe(ip); alive {
				macs[slot] = mac
			}
		}(i, ips[pick])
	}
	wg.Wait()

	for _, mac := range macs {
		if mac == "" || mac != macs[0] {
			return Isolation{}, false
		}
	}
	return Isolation{MAC: macs[0], Probed: probed}, true
}
