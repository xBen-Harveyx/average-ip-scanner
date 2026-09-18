// Package output renders a scan report as a text table, JSON, or CSV.
package output

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/xBen-Harveyx/average-ip-scanner/internal/model"
)

// Table writes the report's hosts as a tab-aligned table. Empty cells render as
// "-"; ports that were never probed render as "?" so an unscanned host is not
// mistaken for one with nothing open.
func Table(w io.Writer, report model.Report) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "HOSTNAME\tIP\tMAC\tMANUFACTURER\tOPEN PORTS")
	for _, h := range report.Hosts {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			dash(h.Hostname), dash(h.IP), dash(h.MAC), dash(h.Manufacturer), portsCell(h))
	}
	tw.Flush()
}

// portsCell renders a host's open ports: "?" when they were never probed, "-"
// when the probe completed and found nothing.
func portsCell(h model.Host) string {
	if !h.PortsScanned {
		return "?"
	}
	return dash(joinPorts(h.OpenPorts, ", "))
}

func joinPorts(ports []int, sep string) string {
	if len(ports) == 0 {
		return ""
	}
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(p)
	}
	return strings.Join(parts, sep)
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
