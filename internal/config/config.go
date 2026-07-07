// Package config parses command-line flags into a validated Config.
package config

import (
	"errors"
	"flag"
	"strings"
	"time"
)

const (
	DefaultWorkers          = 50
	DefaultTimeout          = 0 // no overall timeout; scan runs to completion
	DefaultProgressInterval = 2 * time.Second
)

// Config holds the parsed, validated options for a scan run.
type Config struct {
	Range            string // CIDR to scan; empty means auto-detect the local subnet
	Workers          int
	Timeout          time.Duration
	ProgressInterval time.Duration
	Resolve          bool // reverse-DNS hostname lookup; on by default
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
	}

	fs := flag.NewFlagSet("ais", flag.ContinueOnError)
	fs.SetOutput(new(strings.Builder))

	var noResolve bool
	fs.StringVar(&cfg.Range, "range", "", "CIDR to scan, e.g. 192.168.1.0/24 (default: auto-detect local subnet)")
	fs.IntVar(&cfg.Workers, "workers", cfg.Workers, "Number of concurrent ARP probes")
	fs.DurationVar(&cfg.Timeout, "timeout", cfg.Timeout, "Overall scan timeout such as 30s or 5m (default: no limit)")
	fs.DurationVar(&cfg.ProgressInterval, "progress", cfg.ProgressInterval, "Progress line interval")
	fs.BoolVar(&noResolve, "no-resolve", false, "Skip reverse-DNS hostname lookup")

	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}

	cfg.Range = strings.TrimSpace(cfg.Range)
	cfg.Resolve = !noResolve

	if cfg.Workers <= 0 {
		return Config{}, errors.New("workers must be greater than zero")
	}
	if cfg.Timeout < 0 {
		return Config{}, errors.New("timeout must not be negative")
	}
	if cfg.ProgressInterval <= 0 {
		return Config{}, errors.New("progress interval must be greater than zero")
	}

	return cfg, nil
}
