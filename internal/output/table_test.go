package output

import (
	"strings"
	"testing"

	"github.com/xBen-Harveyx/average-ip-scanner/internal/model"
)

func TestTable(t *testing.T) {
	report := model.Report{Hosts: []model.Host{
		{IP: "192.168.1.1", Hostname: "router.lan", MAC: "aa:bb:cc:dd:ee:ff", Manufacturer: "Acme",
			OpenPorts: []int{80, 443}, PortsScanned: true},
		{IP: "192.168.1.9", MAC: "11:22:33:44:55:66", PortsScanned: true}, // no hostname / vendor
	}}

	var b strings.Builder
	Table(&b, report)
	out := b.String()

	if !strings.Contains(out, "HOSTNAME") || !strings.Contains(out, "MANUFACTURER") {
		t.Errorf("missing header:\n%s", out)
	}
	if !strings.Contains(out, "router.lan") || !strings.Contains(out, "80, 443") {
		t.Errorf("missing first row data:\n%s", out)
	}
	// Empty cells render as "-".
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	last := lines[len(lines)-1]
	if !strings.HasPrefix(last, "-") {
		t.Errorf("expected empty hostname to render as '-', got: %q", last)
	}
}

// The distinction that matters for an audit: a host whose ports were never
// probed must not look identical to one that was probed and came back clean.
func TestTableDistinguishesUnscannedFromNoOpenPorts(t *testing.T) {
	report := model.Report{Hosts: []model.Host{
		{IP: "10.0.0.1", MAC: "aa:bb:cc:dd:ee:01", PortsScanned: false},
		{IP: "10.0.0.2", MAC: "aa:bb:cc:dd:ee:02", PortsScanned: true},
	}}

	var b strings.Builder
	Table(&b, report)
	lines := strings.Split(strings.TrimRight(b.String(), "\n"), "\n")

	unscanned, clean := lines[1], lines[2]
	if !strings.HasSuffix(unscanned, "?") {
		t.Errorf("unscanned host should end in '?', got: %q", unscanned)
	}
	if !strings.HasSuffix(clean, "-") {
		t.Errorf("scanned host with no open ports should end in '-', got: %q", clean)
	}
}
