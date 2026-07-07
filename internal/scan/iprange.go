package scan

import (
	"errors"
	"fmt"
	"net"
)

// maxHosts caps a single scan. ARP is one probe per host, so an accidental
// broad range (say a /8) would hang for a very long time. A /16 is 65,536
// addresses, which is already generous for a "local subnet" tool.
const maxHosts = 1 << 16

// ExpandCIDR returns every usable host address in an IPv4 CIDR block, skipping
// the network and broadcast addresses. A /32 yields the single address and a
// /31 yields both addresses (RFC 3021 point-to-point links have no broadcast).
func ExpandCIDR(cidr string) ([]net.IP, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid range %q: %w", cidr, err)
	}
	if ipNet.IP.To4() == nil {
		return nil, fmt.Errorf("only IPv4 ranges are supported, got %q", cidr)
	}

	ones, bits := ipNet.Mask.Size()
	total := 1 << (bits - ones)
	if total > maxHosts {
		return nil, fmt.Errorf("range %q covers %d addresses, which exceeds the limit of %d; use a smaller range such as a /16 or /24", cidr, total, maxHosts)
	}

	var ips []net.IP
	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); ip = nextIP(ip) {
		clone := make(net.IP, len(ip))
		copy(clone, ip)
		ips = append(ips, clone)
	}

	// For blocks with room to spare, the first address is the network and the
	// last is the broadcast; neither is a real host. /31 and /32 have no such
	// reserved addresses.
	if total >= 4 && len(ips) >= 2 {
		ips = ips[1 : len(ips)-1]
	}
	return ips, nil
}

// nextIP returns the next consecutive address. The input is not modified.
func nextIP(ip net.IP) net.IP {
	next := make(net.IP, len(ip))
	copy(next, ip)
	for i := len(next) - 1; i >= 0; i-- {
		next[i]++
		if next[i] != 0 {
			break
		}
	}
	return next
}

// DetectLocalSubnet returns the CIDR of the first up, non-loopback interface
// with a private IPv4 address. It is used when no explicit range is given.
func DetectLocalSubnet() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("list interfaces: %w", err)
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			v4 := ipNet.IP.To4()
			if v4 == nil || !v4.IsPrivate() {
				continue
			}
			ones, _ := ipNet.Mask.Size()
			network := v4.Mask(ipNet.Mask)
			return fmt.Sprintf("%s/%d", network.String(), ones), nil
		}
	}
	return "", errors.New("no up, non-loopback interface with a private IPv4 address found")
}
