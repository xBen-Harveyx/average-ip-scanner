// Package oui maps MAC address prefixes to hardware manufacturers using an
// embedded, trimmed copy of the IEEE OUI registry.
package oui

import (
	_ "embed"
	"encoding/csv"
	"io"
	"strings"
	"sync"
)

// oui.csv holds two columns: a 6-hex-digit uppercase OUI prefix and the vendor
// name. See README.md for how it is regenerated from the IEEE source.
//
//go:embed oui.csv
var ouiData string

var (
	once  sync.Once
	table map[string]string
)

func load() {
	table = make(map[string]string)
	r := csv.NewReader(strings.NewReader(ouiData))
	r.FieldsPerRecord = 2
	for {
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		table[record[0]] = record[1]
	}
}

// Lookup returns the manufacturer for a MAC address, "(locally administered)"
// for a randomized/locally-administered address, or "" if the prefix is
// unknown. Separators in the input (":", "-", ".") are ignored.
func Lookup(mac string) string {
	hex := normalize(mac)
	if len(hex) < 6 {
		return ""
	}
	if locallyAdministered(hex) {
		return "(locally administered)"
	}
	once.Do(load)
	return table[hex[:6]]
}

func normalize(mac string) string {
	var b strings.Builder
	for _, r := range mac {
		switch {
		case r >= '0' && r <= '9', r >= 'A' && r <= 'F':
			b.WriteRune(r)
		case r >= 'a' && r <= 'f':
			b.WriteRune(r - 'a' + 'A')
		}
	}
	return b.String()
}

// locallyAdministered reports whether the U/L bit (0x02) of the first octet is
// set, marking a locally administered address such as a randomized MAC.
func locallyAdministered(hex string) bool {
	v := fromHexNibble(hex[0])<<4 | fromHexNibble(hex[1])
	return v&0x02 != 0
}

func fromHexNibble(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	default:
		return 0
	}
}
