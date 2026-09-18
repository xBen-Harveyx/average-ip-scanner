package output

import (
	"encoding/json"
	"io"

	"github.com/xBen-Harveyx/average-ip-scanner/internal/model"
)

// reportJSON adds the derived "complete" flag to the wire format. Embedding
// keeps the field names and tags in one place, on model.Report.
type reportJSON struct {
	model.Report
	Complete bool `json:"complete"`
}

// JSON writes the report as a single indented JSON object. Consumers should
// check "complete" before trusting "hosts" as a full picture of the subnet.
func JSON(w io.Writer, report model.Report) error {
	if report.Hosts == nil {
		report.Hosts = []model.Host{} // marshal as [] rather than null
	}
	for i := range report.Hosts {
		if report.Hosts[i].OpenPorts == nil {
			report.Hosts[i].OpenPorts = []int{}
		}
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(reportJSON{Report: report, Complete: report.Complete()})
}
