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

const defaultWorkers = 50

// Options controls a scan. The zero value is not valid; use sensible defaults
// via New-style construction in the caller (see run.Execute).
type Options struct {
	Workers          int
	ProgressInterval time.Duration
	Resolve          bool

	// Injected dependencies. Defaults are applied by Scan when these are nil,
	// which keeps the package testable without real ARP or DNS.
	Probe        func(net.IP) (string, bool)                 // MAC + liveness; defaults to arpProbe
	ResolveHost  func(ctx context.Context, ip string) string // reverse DNS; used when Resolve is true
	LookupVendor func(mac string) string                     // OUI -> manufacturer
	ScanPorts    func(ctx context.Context, ip string) []int  // open-port scan; skipped when nil
	ProgressOut  io.Writer                                   // progress lines; defaults to os.Stderr
}

// Scan probes each IP concurrently and returns the hosts that responded to ARP,
// sorted by IP address. Progress lines are written to Options.ProgressOut.
func Scan(ctx context.Context, ips []net.IP, opts Options) []model.Host {
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
					host.OpenPorts = opts.ScanPorts(ctx, host.IP)
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

	// Progress reporter ticks until told to stop.
	stop := make(chan struct{})
	progressExited := make(chan struct{})
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

	var hosts []model.Host
	for host := range results {
		hosts = append(hosts, host)
	}

	// Stop the ticker, wait for it to exit, then print a definitive final line.
	close(stop)
	<-progressExited
	fmt.Fprintf(opts.ProgressOut, "scanned %d/%d (%d alive)\n", done.Load(), total, alive.Load())

	sort.Slice(hosts, func(i, j int) bool {
		return compareIP(hosts[i].IP, hosts[j].IP) < 0
	})
	return hosts
}

func withDefaults(opts Options) Options {
	if opts.Workers <= 0 {
		opts.Workers = defaultWorkers
	}
	if opts.ProgressInterval <= 0 {
		opts.ProgressInterval = 2 * time.Second
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
