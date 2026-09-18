// Package run wires configuration, scanning, and output into one entry point.
package run

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/xBen-Harveyx/average-ip-scanner/internal/config"
	"github.com/xBen-Harveyx/average-ip-scanner/internal/model"
	"github.com/xBen-Harveyx/average-ip-scanner/internal/oui"
	"github.com/xBen-Harveyx/average-ip-scanner/internal/output"
	"github.com/xBen-Harveyx/average-ip-scanner/internal/ports"
	"github.com/xBen-Harveyx/average-ip-scanner/internal/resolve"
	"github.com/xBen-Harveyx/average-ip-scanner/internal/scan"
)

// ErrIncomplete reports that the scan stopped before covering the whole range,
// so the results are partial. It is returned after the report has already been
// written, so callers still get the data they did collect; it exists to drive a
// non-zero exit code rather than to suppress output.
type ErrIncomplete struct {
	Probed, Total int
	Timeout       time.Duration
}

func (e *ErrIncomplete) Error() string {
	reason := "the scan was cancelled"
	if e.Timeout > 0 {
		reason = fmt.Sprintf("the %s timeout expired", e.Timeout)
	}
	return fmt.Sprintf("scan incomplete: probed %d of %d addresses before %s; results above are partial",
		e.Probed, e.Total, reason)
}

// ErrIsolatedNetwork reports that the target network answers ARP for addresses
// that do not exist, so scanning it would invent a subnet full of devices.
type ErrIsolatedNetwork struct {
	Isolation scan.Isolation
	Range     string
}

func (e *ErrIsolatedNetwork) Error() string {
	return fmt.Sprintf("refusing to scan %s: every probed address answered with the same MAC (%s), "+
		"so this network is answering ARP on behalf of hosts that do not exist "+
		"(guest or client-isolated Wi-Fi). Any result here would be fabricated. "+
		"Pass -ignore-isolation to scan anyway.", e.Range, e.Isolation.MAC)
}

// Execute runs a scan described by cfg: it determines the target range, probes
// every host, and writes the report to stdout with progress on stderr.
func Execute(ctx context.Context, cfg config.Config) error {
	return execute(ctx, cfg, os.Stdout, os.Stderr, nil)
}

// execute is Execute with its side channels injected, so the orchestration can
// be exercised without real ARP or real stdout. A nil probe means the real one.
func execute(ctx context.Context, cfg config.Config, stdout, stderr io.Writer, probe func(net.IP) (string, bool)) error {
	if cfg.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.Timeout)
		defer cancel()
	}

	cidr := cfg.Range
	if cidr == "" {
		detected, err := scan.DetectLocalSubnet()
		if err != nil {
			return fmt.Errorf("auto-detect subnet: %w (pass -range to scan a specific CIDR)", err)
		}
		cidr = detected
		fmt.Fprintf(stderr, "auto-detected local subnet %s\n", cidr)
	}

	ips, err := scan.ExpandCIDR(cidr)
	if err != nil {
		return err
	}

	isolation, isolated := scan.DetectIsolation(ips, probe)
	if isolated {
		if !cfg.IgnoreIsolation {
			return &ErrIsolatedNetwork{Isolation: isolation, Range: cidr}
		}
		fmt.Fprintf(stderr, "warning: %s answers ARP for every address (MAC %s); results are not real hosts\n",
			cidr, isolation.MAC)
	}

	fmt.Fprintf(stderr, "scanning %s (%d hosts)\n", cidr, len(ips))

	var scanPorts func(context.Context, string) ([]int, bool)
	if len(cfg.Ports) > 0 {
		scanPorts = func(ctx context.Context, ip string) ([]int, bool) {
			return ports.Open(ctx, ip, cfg.Ports, cfg.PortTimeout)
		}
	}

	hosts, probed := scan.Scan(ctx, ips, scan.Options{
		Workers:          cfg.Workers,
		ProgressInterval: cfg.ProgressInterval,
		Resolve:          cfg.Resolve,
		Probe:            probe,
		ProgressOut:      stderr,
		ResolveHost:      resolve.Lookup,
		LookupVendor:     oui.Lookup,
		ScanPorts:        scanPorts,
	})

	report := model.Report{
		ScannedAt:       time.Now().UTC(),
		Range:           cidr,
		AddressesTotal:  len(ips),
		AddressesProbed: probed,
		NetworkIsolated: isolated,
		Hosts:           hosts,
	}

	if err := write(stdout, cfg.Format, report); err != nil {
		return fmt.Errorf("write %s output: %w", cfg.Format, err)
	}

	if !report.Complete() {
		err := &ErrIncomplete{Probed: probed, Total: len(ips), Timeout: cfg.Timeout}
		fmt.Fprintf(stderr, "done: %d host(s) responded across %d of %d addresses\n", len(hosts), probed, len(ips))
		return err
	}

	fmt.Fprintf(stderr, "done: %d host(s) responded\n", len(hosts))
	return nil
}

func write(w io.Writer, format string, report model.Report) error {
	switch format {
	case config.FormatJSON:
		return output.JSON(w, report)
	case config.FormatCSV:
		return output.CSV(w, report)
	default:
		output.Table(w, report)
		return nil
	}
}
