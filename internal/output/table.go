// Package output renders scan results as an aligned text table.
package output

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/ben/average-ip-scanner/internal/model"
)

// Print writes hosts as a tab-aligned table. Empty cells render as "-".
// Callers are expected to pass hosts already sorted by IP.
func Print(w io.Writer, hosts []model.Host) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "HOSTNAME\tIP\tMAC\tMANUFACTURER\tOPEN PORTS")
	for _, h := range hosts {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			dash(h.Hostname), dash(h.IP), dash(h.MAC), dash(h.Manufacturer), dash(joinPorts(h.OpenPorts)))
	}
	tw.Flush()
}

func joinPorts(ports []int) string {
	if len(ports) == 0 {
		return ""
	}
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(p)
	}
	return strings.Join(parts, ", ")
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
