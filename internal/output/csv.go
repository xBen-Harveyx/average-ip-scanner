package output

import (
	"encoding/csv"
	"io"
	"strconv"

	"github.com/xBen-Harveyx/average-ip-scanner/internal/model"
)

// CSV writes one row per host with a header. Open ports are space-separated
// within their field, so the value needs no quoting and splits trivially.
//
// Scan metadata is deliberately left out: CSV is a flat host list, and whether
// the scan completed is reported on stderr and by the exit code.
func CSV(w io.Writer, report model.Report) error {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"ip", "hostname", "mac", "manufacturer", "open_ports", "ports_scanned"}); err != nil {
		return err
	}
	for _, h := range report.Hosts {
		row := []string{
			h.IP,
			h.Hostname,
			h.MAC,
			h.Manufacturer,
			joinPorts(h.OpenPorts, " "),
			strconv.FormatBool(h.PortsScanned),
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}
