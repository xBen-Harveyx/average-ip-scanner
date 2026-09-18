package model

import "testing"

func TestReportComplete(t *testing.T) {
	tests := []struct {
		name          string
		probed, total int
		want          bool
	}{
		{"full sweep", 254, 254, true},
		{"cut short", 103, 254, false},
		{"nothing probed", 0, 254, false},
		{"empty range is vacuously complete", 0, 0, true},
		{"probed beyond total still counts as complete", 255, 254, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Report{AddressesProbed: tt.probed, AddressesTotal: tt.total}
			if got := r.Complete(); got != tt.want {
				t.Errorf("Complete() = %v, want %v (probed %d of %d)", got, tt.want, tt.probed, tt.total)
			}
		})
	}
}
