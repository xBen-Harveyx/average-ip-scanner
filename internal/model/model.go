package model

import "time"

// Host is a single discovered device on the local subnet.
type Host struct {
	IP           string `json:"ip"`
	Hostname     string `json:"hostname"`
	MAC          string `json:"mac"` // "aa:bb:cc:dd:ee:ff", empty if unresolved
	Manufacturer string `json:"manufacturer"`

	// OpenPorts holds the open TCP ports found on the host, ascending.
	OpenPorts []int `json:"open_ports"`
	// PortsScanned distinguishes "scanned, nothing open" from "never looked".
	// It is false when port scanning was disabled and when the scan was cut
	// short before this host was probed, so an empty OpenPorts is never
	// mistaken for a clean result.
	PortsScanned bool `json:"ports_scanned"`
}

// Report is the result of one scan: the hosts found plus enough context to
// judge whether the host list can be trusted.
type Report struct {
	ScannedAt       time.Time `json:"scanned_at"`
	Range           string    `json:"range"`
	AddressesTotal  int       `json:"addresses_total"`
	AddressesProbed int       `json:"addresses_probed"`

	// NetworkIsolated marks a scan that ran on a network answering ARP for
	// every address (guest or client-isolated wireless). The hosts below are
	// almost certainly one gateway wearing many addresses, not real devices.
	NetworkIsolated bool `json:"network_isolated"`

	Hosts []Host `json:"hosts"`
}

// Complete reports whether every address in the range was probed. A false
// result means the scan was cut short and the host list is partial.
func (r Report) Complete() bool {
	return r.AddressesProbed >= r.AddressesTotal
}
