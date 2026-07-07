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
		{"-unknown-flag"},
	} {
		if _, err := Parse(args); err == nil {
			t.Errorf("Parse(%v) = nil error, want error", args)
		}
	}
}
