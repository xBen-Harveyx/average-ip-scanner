//go:build ignore

// gen_oui trims the IEEE OUI registry into the two-column CSV embedded by the
// oui package. Usage:
//
//	go run scripts/gen_oui.go <ieee-oui.csv> <out.csv>
//
// The input is the IEEE file (Registry,Assignment,Organization Name,Address);
// the output is PREFIX,Vendor sorted by prefix.
package main

import (
	"encoding/csv"
	"log"
	"os"
	"sort"
	"strings"
)

func main() {
	if len(os.Args) != 3 {
		log.Fatalf("usage: %s <in.csv> <out.csv>", os.Args[0])
	}

	in, err := os.Open(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	defer in.Close()

	rows, err := csv.NewReader(in).ReadAll()
	if err != nil {
		log.Fatal(err)
	}

	type entry struct{ prefix, vendor string }
	var entries []entry
	for i, row := range rows {
		if i == 0 || len(row) < 3 { // skip header and malformed rows
			continue
		}
		prefix := strings.ToUpper(strings.TrimSpace(row[1]))
		vendor := strings.TrimSpace(row[2])
		if len(prefix) != 6 || vendor == "" {
			continue
		}
		entries = append(entries, entry{prefix, vendor})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].prefix < entries[j].prefix })

	out, err := os.Create(os.Args[2])
	if err != nil {
		log.Fatal(err)
	}
	defer out.Close()

	w := csv.NewWriter(out)
	for _, e := range entries {
		if err := w.Write([]string{e.prefix, e.vendor}); err != nil {
			log.Fatal(err)
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		log.Fatal(err)
	}
	log.Printf("wrote %d OUI entries", len(entries))
}
