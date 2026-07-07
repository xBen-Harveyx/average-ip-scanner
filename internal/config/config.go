// Package config parses command-line flags into a validated Config.
package config

import (
	"errors"
	"flag"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ben/average-ip-scanner/internal/ports"
)

const (
	DefaultWorkers          = 50
	DefaultTimeout          = 0 // no overall timeout; scan runs to completion
	DefaultProgressInterval = 2 * time.Second
	DefaultPortTimeout      = 1 * time.Second
)

// Config holds the parsed, validated options for a scan run.
type Config struct {
	Range            string // CIDR to scan; empty means auto-detect the local subnet
	Workers          int
	Timeout          time.Duration
	ProgressInterval time.Duration
	Resolve          bool          // reverse-DNS hostname lookup; on by default
	Ports            []int         // TCP ports to probe on live hosts; empty disables port scanning
	PortTimeout      time.Duration // per-port connect timeout
}

// Parse turns argv-style args into a Config, returning a usage-style error on
// bad input. It does not validate that Range is a well-formed CIDR; that is
// deferred to the scanner so auto-detect ("") stays valid here.
func Parse(args []string) (Config, error) {
	cfg := Config{
		Workers:          DefaultWorkers,
		Timeout:          DefaultTimeout,
		ProgressInterval: DefaultProgressInterval,
		Resolve:          true,
		PortTimeout:      DefaultPortTimeout,
	}

	fs := flag.NewFlagSet("ais", flag.ContinueOnError)
	fs.SetOutput(new(strings.Builder))

	var noResolve, audit bool
	portsFlag := joinInts(ports.DefaultWeb)
	fs.StringVar(&cfg.Range, "range", "", "CIDR to scan, e.g. 192.168.1.0/24 (default: auto-detect local subnet)")
	fs.IntVar(&cfg.Workers, "workers", cfg.Workers, "Number of concurrent ARP probes")
	fs.DurationVar(&cfg.Timeout, "timeout", cfg.Timeout, "Overall scan timeout such as 30s or 5m (default: no limit)")
	fs.DurationVar(&cfg.ProgressInterval, "progress", cfg.ProgressInterval, "Progress line interval")
	fs.BoolVar(&noResolve, "no-resolve", false, "Skip reverse-DNS hostname lookup")
	fs.StringVar(&portsFlag, "ports", portsFlag, "Comma-separated TCP ports to check on live hosts; empty to disable")
	fs.BoolVar(&audit, "audit", false, "Scan a broader security-audit port set (remote access, file sharing, databases); overridden by an explicit -ports")
	fs.DurationVar(&cfg.PortTimeout, "port-timeout", cfg.PortTimeout, "Per-port connect timeout")

	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}

	cfg.Range = strings.TrimSpace(cfg.Range)
	cfg.Resolve = !noResolve

	// An explicit -ports always wins; otherwise -audit swaps in the broader set.
	if audit && !flagSet(fs, "ports") {
		portsFlag = joinInts(ports.Audit)
	}
	parsedPorts, err := parsePorts(portsFlag)
	if err != nil {
		return Config{}, err
	}
	cfg.Ports = parsedPorts

	if cfg.Workers <= 0 {
		return Config{}, errors.New("workers must be greater than zero")
	}
	if cfg.Timeout < 0 {
		return Config{}, errors.New("timeout must not be negative")
	}
	if cfg.ProgressInterval <= 0 {
		return Config{}, errors.New("progress interval must be greater than zero")
	}
	if len(cfg.Ports) > 0 && cfg.PortTimeout <= 0 {
		return Config{}, errors.New("port-timeout must be greater than zero")
	}

	return cfg, nil
}

// parsePorts turns a comma-separated port list into sorted, de-duplicated port
// numbers. An empty or whitespace-only string disables port scanning (nil).
func parsePorts(s string) ([]int, error) {
	seen := make(map[int]bool)
	var out []int
	for _, field := range strings.Split(s, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		port, err := strconv.Atoi(field)
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid port %q: must be a number between 1 and 65535", field)
		}
		if !seen[port] {
			seen[port] = true
			out = append(out, port)
		}
	}
	sort.Ints(out)
	return out, nil
}

// flagSet reports whether the named flag was explicitly provided on the
// command line (as opposed to left at its default).
func flagSet(fs *flag.FlagSet, name string) bool {
	found := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func joinInts(nums []int) string {
	parts := make([]string, len(nums))
	for i, n := range nums {
		parts[i] = strconv.Itoa(n)
	}
	return strings.Join(parts, ",")
}
