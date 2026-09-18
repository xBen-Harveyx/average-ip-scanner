package scan

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xBen-Harveyx/average-ip-scanner/internal/model"
)

// Options controls a scan. The zero value is usable: Scan fills in defaults for
// any unset field via withDefaults.
type Options struct {
	Workers int
	// ProgressInterval is the gap between progress lines. Zero or less disables
	// progress output entirely; the caller owns the default.
	ProgressInterval time.Duration
	Resolve          bool

	// Injected dependencies. Defaults are applied by Scan when these are nil,
	// which keeps the package testable without real ARP or DNS.
	Probe        func(net.IP) (string, bool)                 // MAC + liveness; defaults to arpProbe
	ResolveHost  func(ctx context.Context, ip string) string // reverse DNS; used when Resolve is true
	LookupVendor func(mac string) string                     // OUI -> manufacturer
	// ScanPorts probes a host's TCP ports, returning the open ones and whether
	// the probe completed. Skipped when nil.
	ScanPorts   func(ctx context.Context, ip string) ([]int, bool)
	ProgressOut io.Writer // progress lines; defaults to os.Stderr
}

// Scan probes each IP concurrently and returns the hosts that responded to ARP,
// sorted by IP address, along with the number of addresses actually probed.
//
// A probed count below len(ips) means ctx was cancelled and the scan stopped
// early, so the host list is partial. Callers are expected to check it rather
// than assume a full sweep. Progress lines are written to Options.ProgressOut.
func Scan(ctx context.Context, ips []net.IP, opts Options) (hosts []model.Host, probed int) {
	opts = withDefaults(opts)

	var (
		done  atomic.Int64
		alive atomic.Int64
		total = int64(len(ips))
	)

	jobs := make(chan net.IP)
	results := make(chan model.Host)

	var workers sync.WaitGroup
	for i := 0; i < opts.Workers; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for ip := range jobs {
				mac, ok := opts.Probe(ip)
				done.Add(1)
				if !ok {
					continue
				}
				alive.Add(1)
				host := model.Host{IP: ip.String(), MAC: mac}
				if opts.LookupVendor != nil {
					host.Manufacturer = opts.LookupVendor(mac)
				}
				if opts.Resolve && opts.ResolveHost != nil {
					host.Hostname = opts.ResolveHost(ctx, host.IP)
				}
				if opts.ScanPorts != nil {
					host.OpenPorts, host.PortsScanned = opts.ScanPorts(ctx, host.IP)
				}
				results <- host
			}
		}()
	}

	// Feed jobs, honoring cancellation.
	go func() {
		defer close(jobs)
		for _, ip := range ips {
			select {
			case <-ctx.Done():
				return
			case jobs <- ip:
			}
		}
	}()

	// Close results once every worker has finished.
	go func() {
		workers.Wait()
		close(results)
	}()

	// Progress reporter ticks until told to stop. When progress output is
	// disabled the goroutine never starts, so no ticker is created.
	reportProgress := opts.ProgressInterval > 0
	stop := make(chan struct{})
	progressExited := make(chan struct{})
	if reportProgress {
		go func() {
			defer close(progressExited)
			ticker := time.NewTicker(opts.ProgressInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					fmt.Fprintf(opts.ProgressOut, "scanned %d/%d (%d alive)\n", done.Load(), total, alive.Load())
				case <-stop:
					return
				}
			}
		}()
	}

	for host := range results {
		hosts = append(hosts, host)
	}

	// Stop the ticker, wait for it to exit, then print a definitive final line.
	if reportProgress {
		close(stop)
		<-progressExited
		fmt.Fprintf(opts.ProgressOut, "scanned %d/%d (%d alive)\n", done.Load(), total, alive.Load())
	}

	sort.Slice(hosts, func(i, j int) bool {
		return compareIP(hosts[i].IP, hosts[j].IP) < 0
	})
	return hosts, int(done.Load())
}

func withDefaults(opts Options) Options {
	// A guard, not a default: the user-facing default lives with the flag in
	// the config package. Zero workers would consume no jobs and quietly
	// return an empty result, which is worse than a slow scan.
	if opts.Workers <= 0 {
		opts.Workers = 1
	}
	if opts.Probe == nil {
		opts.Probe = arpProbe
	}
	if opts.ProgressOut == nil {
		opts.ProgressOut = os.Stderr
	}
	return opts
}

// compareIP orders two IPv4 address strings numerically. Unparseable inputs
// sort last, deterministically.
func compareIP(a, b string) int {
	ipA, ipB := net.ParseIP(a).To4(), net.ParseIP(b).To4()
	switch {
	case ipA == nil && ipB == nil:
		return 0
	case ipA == nil:
		return 1
	case ipB == nil:
		return -1
	}
	for i := 0; i < 4; i++ {
		if ipA[i] != ipB[i] {
			return int(ipA[i]) - int(ipB[i])
		}
	}
	return 0
}
