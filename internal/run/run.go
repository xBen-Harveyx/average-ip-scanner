// Package run wires configuration, scanning, and output into one entry point.
package run

import (
	"context"
	"fmt"
	"os"

	"github.com/xBen-Harveyx/average-ip-scanner/internal/config"
	"github.com/xBen-Harveyx/average-ip-scanner/internal/output"
	"github.com/xBen-Harveyx/average-ip-scanner/internal/oui"
	"github.com/xBen-Harveyx/average-ip-scanner/internal/ports"
	"github.com/xBen-Harveyx/average-ip-scanner/internal/resolve"
	"github.com/xBen-Harveyx/average-ip-scanner/internal/scan"
)

// Execute runs a scan described by cfg: it determines the target range, probes
// every host, and prints a table to stdout with progress on stderr.
func Execute(ctx context.Context, cfg config.Config) error {
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
		fmt.Fprintf(os.Stderr, "auto-detected local subnet %s\n", cidr)
	}

	ips, err := scan.ExpandCIDR(cidr)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "scanning %s (%d hosts)\n", cidr, len(ips))

	var scanPorts func(context.Context, string) []int
	if len(cfg.Ports) > 0 {
		scanPorts = func(ctx context.Context, ip string) []int {
			return ports.Open(ctx, ip, cfg.Ports, cfg.PortTimeout)
		}
	}

	hosts := scan.Scan(ctx, ips, scan.Options{
		Workers:          cfg.Workers,
		ProgressInterval: cfg.ProgressInterval,
		Resolve:          cfg.Resolve,
		ResolveHost:      resolve.Lookup,
		LookupVendor:     oui.Lookup,
		ScanPorts:        scanPorts,
	})

	output.Print(os.Stdout, hosts)
	fmt.Fprintf(os.Stderr, "done: %d host(s) responded\n", len(hosts))
	return nil
}
