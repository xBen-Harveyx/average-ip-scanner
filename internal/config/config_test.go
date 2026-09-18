package config

import (
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParseDefaults(t *testing.T) {
	cfg, err := Parse(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Range != "" {
		t.Errorf("Range = %q, want empty (auto-detect)", cfg.Range)
	}
	if cfg.Workers != DefaultWorkers {
		t.Errorf("Workers = %d, want %d", cfg.Workers, DefaultWorkers)
	}
	if !cfg.Resolve {
		t.Error("Resolve = false, want true by default")
	}
}

func TestParseFlags(t *testing.T) {
	cfg, err := Parse([]string{
		"-range", "192.168.1.0/24",
		"-workers", "100",
		"-timeout", "45s",
		"-progress", "1s",
		"-no-resolve",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Range != "192.168.1.0/24" {
		t.Errorf("Range = %q", cfg.Range)
	}
	if cfg.Workers != 100 {
		t.Errorf("Workers = %d, want 100", cfg.Workers)
	}
	if cfg.Timeout != 45*time.Second {
		t.Errorf("Timeout = %v, want 45s", cfg.Timeout)
	}
	if cfg.Resolve {
		t.Error("Resolve = true, want false with -no-resolve")
	}
}

func TestParseRejectsBadValues(t *testing.T) {
	for _, args := range [][]string{
		{"-workers", "0"},
		{"-timeout", "-5s"},
		{"-progress", "-1s"},
		{"-ports", "80,notaport"},
		{"-ports", "70000"},
		{"-format", "yaml"},
		{"-unknown-flag"},
	} {
		if _, err := Parse(args); err == nil {
			t.Errorf("Parse(%v) = nil error, want error", args)
		}
	}
}

func TestParsePorts(t *testing.T) {
	// Default: the built-in web port set.
	cfg, err := Parse(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Ports) == 0 {
		t.Error("default Ports is empty, want the web port set")
	}

	// Explicit list is de-duplicated and sorted.
	cfg, err = Parse([]string{"-ports", "443, 80, 80, 8080"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []int{80, 443, 8080}
	if len(cfg.Ports) != len(want) {
		t.Fatalf("Ports = %v, want %v", cfg.Ports, want)
	}
	for i := range want {
		if cfg.Ports[i] != want[i] {
			t.Fatalf("Ports = %v, want %v", cfg.Ports, want)
		}
	}

	// Empty value disables port scanning.
	cfg, err = Parse([]string{"-ports", ""})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Ports) != 0 {
		t.Errorf("Ports = %v, want empty (disabled)", cfg.Ports)
	}
}

func TestParseAuditPreset(t *testing.T) {
	web, err := Parse(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	audit, err := Parse([]string{"-audit"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(audit.Ports) <= len(web.Ports) {
		t.Errorf("-audit ports (%d) should be broader than default (%d)", len(audit.Ports), len(web.Ports))
	}
	if !contains(audit.Ports, 3389) {
		t.Errorf("-audit should include RDP (3389), got %v", audit.Ports)
	}

	// An explicit -ports overrides -audit.
	override, err := Parse([]string{"-audit", "-ports", "80,443"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(override.Ports) != 2 {
		t.Errorf("explicit -ports should override -audit, got %v", override.Ports)
	}
}

func TestParseFormat(t *testing.T) {
	cfg, err := Parse(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Format != FormatTable {
		t.Errorf("default Format = %q, want %q", cfg.Format, FormatTable)
	}

	for _, want := range []string{FormatTable, FormatJSON, FormatCSV} {
		cfg, err := Parse([]string{"-format", want})
		if err != nil {
			t.Fatalf("Parse(-format %s): %v", want, err)
		}
		if cfg.Format != want {
			t.Errorf("Format = %q, want %q", cfg.Format, want)
		}
	}

	// Case and surrounding whitespace are normalized.
	cfg, err = Parse([]string{"-format", "  JSON "})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Format != FormatJSON {
		t.Errorf("Format = %q, want %q", cfg.Format, FormatJSON)
	}
}

func contains(nums []int, target int) bool {
	for _, n := range nums {
		if n == target {
			return true
		}
	}
	return false
}

// Zero is how progress output is turned off, so it must not be an error.
func TestParseProgressZeroDisables(t *testing.T) {
	cfg, err := Parse([]string{"-progress", "0"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ProgressInterval != 0 {
		t.Errorf("ProgressInterval = %v, want 0 (disabled)", cfg.ProgressInterval)
	}
}

// Each worker parks in a blocking syscall, which costs an OS thread, so the
// count has to stay well under the runtime's thread ceiling.
func TestParseRejectsExcessiveWorkers(t *testing.T) {
	if _, err := Parse([]string{"-workers", "20000"}); err == nil {
		t.Error("Parse(-workers 20000) = nil error, want a cap violation")
	}
	if _, err := Parse([]string{"-workers", strconv.Itoa(MaxWorkers)}); err != nil {
		t.Errorf("Parse(-workers %d) = %v, want the cap itself to be allowed", MaxWorkers, err)
	}
}

func TestParseVersionExitsEarly(t *testing.T) {
	_, err := Parse([]string{"-version"})

	var early *EarlyExit
	if !errors.As(err, &early) {
		t.Fatalf("Parse(-version) = %v, want *EarlyExit", err)
	}
	if !strings.HasPrefix(early.Output, "ais ") {
		t.Errorf("version output = %q, want it to start with %q", early.Output, "ais ")
	}
}

// -h must produce a real flag listing, not a bare "flag: help requested".
func TestParseHelpPrintsUsage(t *testing.T) {
	_, err := Parse([]string{"-h"})

	var early *EarlyExit
	if !errors.As(err, &early) {
		t.Fatalf("Parse(-h) = %v, want *EarlyExit", err)
	}
	for _, want := range []string{"Usage:", "-range", "-audit", "-format", "-workers"} {
		if !strings.Contains(early.Output, want) {
			t.Errorf("usage text is missing %q:\n%s", want, early.Output)
		}
	}
}

// An unknown flag should explain itself and list the valid flags.
func TestParseUnknownFlagIncludesUsage(t *testing.T) {
	_, err := Parse([]string{"-bogus"})
	if err == nil {
		t.Fatal("Parse(-bogus) = nil error, want a usage error")
	}
	var early *EarlyExit
	if errors.As(err, &early) {
		t.Fatal("an unknown flag must not be treated as an early exit")
	}
	if !strings.Contains(err.Error(), "-bogus") || !strings.Contains(err.Error(), "-range") {
		t.Errorf("error should name the bad flag and list valid ones:\n%s", err)
	}
}

// EarlyExit doubles as an error so it can travel up the normal error path,
// but its message is the output the user asked for.
func TestEarlyExitErrorIsItsOutput(t *testing.T) {
	e := &EarlyExit{Output: "ais 1.2.3\n"}
	if e.Error() != "ais 1.2.3\n" {
		t.Errorf("Error() = %q, want it to be the output verbatim", e.Error())
	}
}
