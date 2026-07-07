// Package ports performs lightweight TCP connect scans to detect open ports on
// a host. A successful connection means the port is open (something is
// listening); a refused or timed-out connection is treated as closed.
package ports

import (
	"context"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"
)

// DefaultWeb is the set of common web-service ports scanned by default: the
// standard HTTP/HTTPS ports plus the alternate ports admin panels and embedded
// device UIs commonly listen on.
var DefaultWeb = []int{80, 443, 8000, 8080, 8443, 8888}

// Audit is a broader set for attack-surface reviews, enabled by -audit. Beyond
// web/admin panels it covers remote-access (RDP, SSH, Telnet, VNC, WinRM),
// file sharing (FTP, SMB), raw printing, and database ports that should rarely
// be reachable from client machines.
var Audit = []int{
	21,    // FTP
	22,    // SSH
	23,    // Telnet
	80,    // HTTP
	139,   // NetBIOS
	443,   // HTTPS
	445,   // SMB
	1433,  // MSSQL
	3306,  // MySQL
	3389,  // RDP
	5432,  // PostgreSQL
	5900,  // VNC
	5985,  // WinRM (HTTP)
	5986,  // WinRM (HTTPS)
	6379,  // Redis
	8006,  // Proxmox
	8080,  // HTTP alt
	8081,  // HTTP alt
	8443,  // HTTPS alt
	8843,  // UniFi
	8880,  // UniFi
	8888,  // HTTP alt
	9000,  // Portainer / misc admin
	9100,  // Raw printing (JetDirect)
	10000, // Webmin
	27017, // MongoDB
}

// Open returns the subset of ports on ip that accept a TCP connection, sorted
// ascending. Each port is probed concurrently with its own timeout.
func Open(ctx context.Context, ip string, ports []int, timeout time.Duration) []int {
	var (
		mu   sync.Mutex
		open []int
		wg   sync.WaitGroup
	)
	for _, p := range ports {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			if dialOpen(ctx, ip, port, timeout) {
				mu.Lock()
				open = append(open, port)
				mu.Unlock()
			}
		}(p)
	}
	wg.Wait()

	sort.Ints(open)
	return open
}

func dialOpen(ctx context.Context, ip string, port int, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
