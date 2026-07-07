package config

import (
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

func contains(nums []int, target int) bool {
	for _, n := range nums {
		if n == target {
			return true
		}
	}
	return false
}
