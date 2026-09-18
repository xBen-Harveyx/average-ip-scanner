package output

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/xBen-Harveyx/average-ip-scanner/internal/model"
)

func sampleReport() model.Report {
	return model.Report{
		ScannedAt:       time.Date(2026, 9, 18, 10, 0, 0, 0, time.UTC),
		Range:           "192.168.1.0/24",
		AddressesTotal:  254,
		AddressesProbed: 254,
		Hosts: []model.Host{
			{IP: "192.168.1.1", Hostname: "gw.lan", MAC: "aa:bb:cc:dd:ee:ff",
				Manufacturer: "Acme", OpenPorts: []int{80, 443}, PortsScanned: true},
			{IP: "192.168.1.9", MAC: "11:22:33:44:55:66", PortsScanned: false},
		},
	}
}

func TestJSONShape(t *testing.T) {
	var b strings.Builder
	if err := JSON(&b, sampleReport()); err != nil {
		t.Fatalf("JSON: %v", err)
	}

	var got struct {
		Range           string `json:"range"`
		Complete        bool   `json:"complete"`
		AddressesProbed int    `json:"addresses_probed"`
		Hosts           []struct {
			IP           string `json:"ip"`
			OpenPorts    []int  `json:"open_ports"`
			PortsScanned bool   `json:"ports_scanned"`
		} `json:"hosts"`
	}
	if err := json.Unmarshal([]byte(b.String()), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, b.String())
	}

	if got.Range != "192.168.1.0/24" || got.AddressesProbed != 254 {
		t.Errorf("metadata not carried through: %+v", got)
	}
	if !got.Complete {
		t.Error("complete = false, want true for a full sweep")
	}
	if len(got.Hosts) != 2 || got.Hosts[0].IP != "192.168.1.1" {
		t.Fatalf("hosts = %+v", got.Hosts)
	}
	if got.Hosts[1].PortsScanned {
		t.Error("second host should be marked as not port-scanned")
	}
}

func TestJSONMarksPartialScanIncomplete(t *testing.T) {
	report := sampleReport()
	report.AddressesProbed = 99

	var b strings.Builder
	if err := JSON(&b, report); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if !strings.Contains(b.String(), `"complete": false`) {
		t.Errorf("partial scan not flagged incomplete:\n%s", b.String())
	}
}

// Nil slices must marshal as [] so consumers can iterate without a null check.
func TestJSONEmptyCollectionsAreArrays(t *testing.T) {
	report := model.Report{Hosts: nil}

	var b strings.Builder
	if err := JSON(&b, report); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	out := b.String()
	if strings.Contains(out, "null") {
		t.Errorf("output contains null instead of an empty array:\n%s", out)
	}
}

func TestCSVRows(t *testing.T) {
	var b strings.Builder
	if err := CSV(&b, sampleReport()); err != nil {
		t.Fatalf("CSV: %v", err)
	}

	rows, err := csv.NewReader(strings.NewReader(b.String())).ReadAll()
	if err != nil {
		t.Fatalf("output is not valid CSV: %v\n%s", err, b.String())
	}
	if len(rows) != 3 {
		t.Fatalf("got %d rows (incl. header), want 3", len(rows))
	}
	if rows[0][0] != "ip" || rows[0][5] != "ports_scanned" {
		t.Errorf("unexpected header: %v", rows[0])
	}
	if rows[1][4] != "80 443" {
		t.Errorf("open_ports = %q, want %q", rows[1][4], "80 443")
	}
	if rows[1][5] != "true" || rows[2][5] != "false" {
		t.Errorf("ports_scanned not carried through: %v / %v", rows[1], rows[2])
	}
}

// A scan that finds nothing is a normal outcome. Every format must still
// produce well-formed output with its headers intact.
func TestEmptyReportInEveryFormat(t *testing.T) {
	empty := model.Report{Range: "10.0.0.0/24", AddressesTotal: 254, AddressesProbed: 254}

	var b strings.Builder
	Table(&b, empty)
	if !strings.Contains(b.String(), "HOSTNAME") {
		t.Errorf("empty table lost its header:\n%s", b.String())
	}

	b.Reset()
	if err := JSON(&b, empty); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var decoded struct {
		Hosts    []model.Host `json:"hosts"`
		Complete bool         `json:"complete"`
	}
	if err := json.Unmarshal([]byte(b.String()), &decoded); err != nil {
		t.Fatalf("empty report is not valid JSON: %v", err)
	}
	if decoded.Hosts == nil {
		t.Error("hosts decoded as nil, want an empty array")
	}
	if !decoded.Complete {
		t.Error("an empty but full sweep should still report complete")
	}

	b.Reset()
	if err := CSV(&b, empty); err != nil {
		t.Fatalf("CSV: %v", err)
	}
	rows, err := csv.NewReader(strings.NewReader(b.String())).ReadAll()
	if err != nil {
		t.Fatalf("empty report is not valid CSV: %v", err)
	}
	if len(rows) != 1 || rows[0][0] != "ip" {
		t.Errorf("empty CSV should be header-only, got %v", rows)
	}
}

// failingWriter rejects every write, standing in for a closed pipe or a full
// disk when output is redirected.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

// A broken stdout must surface as an error rather than being swallowed, so the
// caller can exit non-zero instead of reporting a successful empty scan.
func TestCSVPropagatesWriteErrors(t *testing.T) {
	if err := CSV(failingWriter{}, sampleReport()); err == nil {
		t.Error("CSV = nil error on a failing writer, want the failure surfaced")
	}
}

func TestJSONPropagatesWriteErrors(t *testing.T) {
	if err := JSON(failingWriter{}, sampleReport()); err == nil {
		t.Error("JSON = nil error on a failing writer, want the failure surfaced")
	}
}
