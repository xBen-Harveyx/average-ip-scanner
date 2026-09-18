package run

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/xBen-Harveyx/average-ip-scanner/internal/config"
	"github.com/xBen-Harveyx/average-ip-scanner/internal/model"
	"github.com/xBen-Harveyx/average-ip-scanner/internal/scan"
)

func sampleReport() model.Report {
	return model.Report{
		ScannedAt:       time.Date(2026, 9, 18, 10, 0, 0, 0, time.UTC),
		Range:           "192.168.1.0/24",
		AddressesTotal:  254,
		AddressesProbed: 254,
		Hosts: []model.Host{
			{IP: "192.168.1.1", MAC: "aa:bb:cc:dd:ee:ff", OpenPorts: []int{80}, PortsScanned: true},
		},
	}
}

func TestWriteDispatchesByFormat(t *testing.T) {
	var b strings.Builder
	if err := write(&b, config.FormatJSON, sampleReport()); err != nil {
		t.Fatalf("json: %v", err)
	}
	if !json.Valid([]byte(b.String())) {
		t.Errorf("FormatJSON did not produce valid JSON:\n%s", b.String())
	}

	b.Reset()
	if err := write(&b, config.FormatCSV, sampleReport()); err != nil {
		t.Fatalf("csv: %v", err)
	}
	if _, err := csv.NewReader(strings.NewReader(b.String())).ReadAll(); err != nil {
		t.Errorf("FormatCSV did not produce valid CSV: %v\n%s", err, b.String())
	}

	b.Reset()
	if err := write(&b, config.FormatTable, sampleReport()); err != nil {
		t.Fatalf("table: %v", err)
	}
	if !strings.Contains(b.String(), "HOSTNAME") {
		t.Errorf("FormatTable did not produce a table:\n%s", b.String())
	}
}

// An unrecognised format should still produce output rather than nothing;
// config rejects bad values long before this point.
func TestWriteFallsBackToTable(t *testing.T) {
	var b strings.Builder
	if err := write(&b, "unrecognised", sampleReport()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(b.String(), "HOSTNAME") {
		t.Errorf("unknown format should fall back to the table:\n%s", b.String())
	}
}

// The incomplete message drives an operator's read of a partial scan, so it has
// to name the shortfall and why it happened.
func TestErrIncompleteMessage(t *testing.T) {
	timedOut := (&ErrIncomplete{Probed: 103, Total: 254, Timeout: 5 * time.Second}).Error()
	for _, want := range []string{"103", "254", "5s", "timeout", "partial"} {
		if !strings.Contains(timedOut, want) {
			t.Errorf("timeout message missing %q: %s", want, timedOut)
		}
	}

	// Without a timeout the cause is a cancelled context, not an expiry.
	cancelled := (&ErrIncomplete{Probed: 10, Total: 254}).Error()
	if strings.Contains(cancelled, "timeout expired") {
		t.Errorf("cancelled scan should not blame a timeout: %s", cancelled)
	}
	if !strings.Contains(cancelled, "cancelled") {
		t.Errorf("cancelled message should say so: %s", cancelled)
	}
}

// The isolation refusal is the only thing an operator sees when the tool
// declines to scan, so it must explain itself and name the escape hatch.
func TestErrIsolatedNetworkMessage(t *testing.T) {
	err := &ErrIsolatedNetwork{
		Range:     "172.16.0.0/24",
		Isolation: scan.Isolation{MAC: "44:12:44:c6:89:2c"},
	}

	msg := err.Error()
	for _, want := range []string{"172.16.0.0/24", "44:12:44:c6:89:2c", "-ignore-isolation"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message missing %q: %s", want, msg)
		}
	}
}

// uniformProbe stands in for a proxy-ARP network: every address answers with
// the same MAC.
func uniformProbe(mac string) func(net.IP) (string, bool) {
	return func(net.IP) (string, bool) { return mac, true }
}

// sparseProbe stands in for a normal subnet: only the listed hosts answer.
func sparseProbe(live map[string]string) func(net.IP) (string, bool) {
	return func(ip net.IP) (string, bool) {
		mac, ok := live[ip.String()]
		return mac, ok
	}
}

func testConfig(cidr string) config.Config {
	return config.Config{
		Range:            cidr,
		Workers:          8,
		ProgressInterval: 0,     // keep test output quiet
		Resolve:          false, // no real DNS in tests
		Format:           config.FormatJSON,
	}
}

func decodeReport(t *testing.T, s string) map[string]any {
	t.Helper()
	var got map[string]any
	if err := json.Unmarshal([]byte(s), &got); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, s)
	}
	return got
}

// The headline protection: a proxy-ARP network must produce no report at all,
// so nothing fabricated can reach a UDF or a parser downstream.
func TestExecuteRefusesIsolatedNetwork(t *testing.T) {
	var stdout, stderr strings.Builder

	err := execute(context.Background(), testConfig("10.9.0.0/24"), &stdout, &stderr,
		uniformProbe("44:12:44:c6:89:2c"))

	var isolated *ErrIsolatedNetwork
	if !errors.As(err, &isolated) {
		t.Fatalf("execute = %v, want *ErrIsolatedNetwork", err)
	}
	if stdout.String() != "" {
		t.Errorf("a refused scan must write nothing to stdout, got:\n%s", stdout.String())
	}
}

// With the override the scan proceeds, but the report has to carry the warning
// forward so a consumer can still tell the hosts are not real.
func TestExecuteIgnoreIsolationFlagsTheReport(t *testing.T) {
	var stdout, stderr strings.Builder

	cfg := testConfig("10.9.0.0/24")
	cfg.IgnoreIsolation = true

	if err := execute(context.Background(), cfg, &stdout, &stderr, uniformProbe("44:12:44:c6:89:2c")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := decodeReport(t, stdout.String())
	if got["network_isolated"] != true {
		t.Errorf("network_isolated = %v, want true", got["network_isolated"])
	}
	if !strings.Contains(stderr.String(), "not real hosts") {
		t.Errorf("stderr should warn about the isolated network, got:\n%s", stderr.String())
	}
}

func TestExecuteCompleteScan(t *testing.T) {
	var stdout, stderr strings.Builder

	live := map[string]string{
		"10.9.0.5": "aa:bb:cc:00:00:05",
		"10.9.0.9": "aa:bb:cc:00:00:09",
	}
	if err := execute(context.Background(), testConfig("10.9.0.0/24"), &stdout, &stderr, sparseProbe(live)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := decodeReport(t, stdout.String())
	if got["complete"] != true {
		t.Errorf("complete = %v, want true", got["complete"])
	}
	if got["network_isolated"] != false {
		t.Errorf("network_isolated = %v, want false on a normal subnet", got["network_isolated"])
	}
	hosts, _ := got["hosts"].([]any)
	if len(hosts) != len(live) {
		t.Errorf("found %d hosts, want %d", len(hosts), len(live))
	}
	// Port scanning was off, so no host may claim it was checked.
	for _, h := range hosts {
		if h.(map[string]any)["ports_scanned"] != false {
			t.Error("ports_scanned = true with port scanning disabled")
		}
	}
}

// A scan cut short must report itself as incomplete and return an error, so the
// process exits non-zero rather than passing off a partial sweep as a full one.
func TestExecuteCancelledScanReportsIncomplete(t *testing.T) {
	var stdout, stderr strings.Builder

	ctx, cancel := context.WithCancel(context.Background())
	var calls int
	probe := func(net.IP) (string, bool) {
		calls++
		if calls > 5 {
			cancel()
		}
		return "", false
	}

	cfg := testConfig("10.9.0.0/24")
	cfg.Workers = 1 // deterministic cancel point
	err := execute(ctx, cfg, &stdout, &stderr, probe)
	defer cancel()

	var incomplete *ErrIncomplete
	if !errors.As(err, &incomplete) {
		t.Fatalf("execute = %v, want *ErrIncomplete", err)
	}
	if incomplete.Probed >= incomplete.Total {
		t.Errorf("probed %d of %d, want a shortfall", incomplete.Probed, incomplete.Total)
	}
	// The data collected so far is still written out.
	if got := decodeReport(t, stdout.String()); got["complete"] != false {
		t.Errorf("complete = %v, want false", got["complete"])
	}
}

func TestExecuteRejectsBadRange(t *testing.T) {
	var stdout, stderr strings.Builder
	if err := execute(context.Background(), testConfig("not-a-cidr"), &stdout, &stderr, nil); err == nil {
		t.Error("execute = nil error on a malformed range, want a failure")
	}
}

// With no -range, the target comes from the machine's own routing.
func TestExecuteAutoDetectsRange(t *testing.T) {
	if _, err := scan.DetectLocalSubnet(); err != nil {
		t.Skipf("no detectable local subnet here: %v", err)
	}

	var stdout, stderr strings.Builder
	cfg := testConfig("") // empty range triggers auto-detect

	if err := execute(context.Background(), cfg, &stdout, &stderr, sparseProbe(nil)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(stderr.String(), "auto-detected local subnet") {
		t.Errorf("stderr should name the detected subnet, got:\n%s", stderr.String())
	}
	got := decodeReport(t, stdout.String())
	if _, _, err := net.ParseCIDR(got["range"].(string)); err != nil {
		t.Errorf("reported range %q is not a CIDR", got["range"])
	}
}

// The port-scan wiring, end to end against a real listening socket.
func TestExecuteScansPorts(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	openPort := ln.Addr().(*net.TCPAddr).Port

	var stdout, stderr strings.Builder
	cfg := testConfig("127.0.0.0/30")
	cfg.Ports = []int{openPort}
	cfg.PortTimeout = 2 * time.Second

	probe := sparseProbe(map[string]string{"127.0.0.1": "aa:bb:cc:00:00:01"})
	if err := execute(context.Background(), cfg, &stdout, &stderr, probe); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	hosts := decodeReport(t, stdout.String())["hosts"].([]any)
	if len(hosts) != 1 {
		t.Fatalf("got %d hosts, want 1", len(hosts))
	}
	host := hosts[0].(map[string]any)
	if host["ports_scanned"] != true {
		t.Error("ports_scanned = false, want true")
	}
	ports := host["open_ports"].([]any)
	if len(ports) != 1 || int(ports[0].(float64)) != openPort {
		t.Errorf("open_ports = %v, want [%d]", ports, openPort)
	}
}

// A broken stdout must fail the run rather than silently reporting success.
func TestExecuteSurfacesWriteFailure(t *testing.T) {
	var stderr strings.Builder

	err := execute(context.Background(), testConfig("10.9.0.0/24"), failingWriter{}, &stderr, sparseProbe(nil))
	if err == nil {
		t.Fatal("execute = nil error with an unwritable stdout, want a failure")
	}
	if !strings.Contains(err.Error(), "write") {
		t.Errorf("error should name the write failure: %v", err)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

// Execute is the thin wrapper that binds the real stdout and stderr; a bad
// range fails before anything is written.
func TestExecuteWrapperPropagatesErrors(t *testing.T) {
	if err := Execute(context.Background(), testConfig("not-a-cidr")); err == nil {
		t.Error("Execute = nil error on a malformed range, want a failure")
	}
}
