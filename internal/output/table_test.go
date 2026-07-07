package output

import (
	"strings"
	"testing"

	"github.com/ben/average-ip-scanner/internal/model"
)

func TestPrint(t *testing.T) {
	hosts := []model.Host{
		{IP: "192.168.1.1", Hostname: "router.lan", MAC: "aa:bb:cc:dd:ee:ff", Manufacturer: "Acme"},
		{IP: "192.168.1.9", MAC: "11:22:33:44:55:66"}, // no hostname / vendor
	}

	var b strings.Builder
	Print(&b, hosts)
	out := b.String()

	if !strings.Contains(out, "HOSTNAME") || !strings.Contains(out, "MANUFACTURER") {
		t.Errorf("missing header:\n%s", out)
	}
	if !strings.Contains(out, "router.lan") || !strings.Contains(out, "aa:bb:cc:dd:ee:ff") {
		t.Errorf("missing first row data:\n%s", out)
	}
	// Empty cells render as "-".
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	last := lines[len(lines)-1]
	if !strings.HasPrefix(last, "-") {
		t.Errorf("expected empty hostname to render as '-', got: %q", last)
	}
}
