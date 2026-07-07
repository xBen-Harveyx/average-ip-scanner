package model

// Host is a single discovered device on the local subnet.
type Host struct {
	IP           string
	Hostname     string
	MAC          string // "aa:bb:cc:dd:ee:ff", empty if unresolved
	Manufacturer string
	OpenPorts    []int // open TCP ports found on the host, ascending; nil if port scanning is disabled
}
