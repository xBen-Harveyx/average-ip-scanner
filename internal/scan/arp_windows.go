//go:build windows

package scan

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

var (
	iphlpapiDLL = syscall.NewLazyDLL("iphlpapi.dll")
	sendARPProc = iphlpapiDLL.NewProc("SendARP")
)

// arpProbe resolves the MAC address of an on-subnet IPv4 host via the Windows
// SendARP API. A successful call means the host answered ARP, so it doubles as
// the liveness check: (mac, true) for a present host, ("", false) otherwise.
//
// SendARP works only for hosts on the same Layer-2 segment and needs no
// elevated privileges.
//
//	DWORD SendARP(IPAddr DestIP, IPAddr SrcIP, PVOID pMacAddr, PULONG PhyAddrLen);
func arpProbe(ip net.IP) (string, bool) {
	v4 := ip.To4()
	if v4 == nil {
		return "", false
	}

	// Windows IPAddr is in network byte order: the low-order byte is the first
	// octet, so a little-endian read of the 4 octets produces the right DWORD.
	dest := binary.LittleEndian.Uint32(v4)

	var mac [8]byte
	macLen := uint32(len(mac))

	ret, _, _ := sendARPProc.Call(
		uintptr(dest),
		0, // SrcIP 0: let Windows pick the source interface.
		uintptr(unsafe.Pointer(&mac[0])),
		uintptr(unsafe.Pointer(&macLen)),
	)
	if ret != 0 || macLen == 0 {
		return "", false
	}
	return formatMAC(mac[:macLen]), true
}

func formatMAC(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	s := fmt.Sprintf("%02x", b[0])
	for _, c := range b[1:] {
		s += fmt.Sprintf(":%02x", c)
	}
	return s
}
