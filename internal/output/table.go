// Package output renders scan results as an aligned text table.
package output

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/ben/average-ip-scanner/internal/model"
)

// Print writes hosts as a tab-aligned table. Empty cells render as "-".
// Callers are expected to pass hosts already sorted by IP.
func Print(w io.Writer, hosts []model.Host) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "HOSTNAME\tIP\tMAC\tMANUFACTURER")
	for _, h := range hosts {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n",
			dash(h.Hostname), dash(h.IP), dash(h.MAC), dash(h.Manufacturer))
	}
	tw.Flush()
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
