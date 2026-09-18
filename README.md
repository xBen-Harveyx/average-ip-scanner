# average-ip-scanner (`ais`)

A small AdvancedIPScanner-style CLI for Windows. Run it on a machine connected
to a network and it prints a table of live hosts on the **local subnet** with
their hostname, IP, MAC address, hardware manufacturer, and any open web ports.

The open-port check is a lightweight TCP connect scan of live hosts, aimed at
surfacing exposed web interfaces (router/admin panels, IoT device UIs) that may
need to be locked down.

It is built to run non-interactively through an RMM tool:

- Single self-contained binary (the OUI vendor database is embedded).
- Refuses to scan a guest or client-isolated network, where every address
  answers and the results would be invented.
- **No administrator rights required** — discovery uses the Windows `SendARP`
  API, which resolves each host's MAC and liveness in one call.
- The results table goes to **stdout**; progress and status go to **stderr**, as
  plain text lines (no ANSI/TUI), so captured RMM logs stay clean.

Because it relies on ARP, it only sees hosts on the same Layer-2 subnet — which
is exactly where MAC addresses and manufacturers are meaningful.

## Usage

```
ais [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `-range` | auto-detect local subnet | CIDR to scan, e.g. `192.168.1.0/24` |
| `-workers` | `50` | Number of concurrent ARP probes |
| `-timeout` | none | Overall scan timeout, e.g. `30s` or `5m` (default: no limit) |
| `-progress` | `2s` | Interval between progress lines on stderr; `0` disables them |
| `-no-resolve` | off | Skip reverse-DNS hostname lookups |
| `-ports` | `80,443,8000,8080,8443,8888` | Comma-separated TCP ports to check on live hosts; empty (`-ports ""`) disables port scanning |
| `-audit` | off | Use a broader security-audit port set instead of the web default (see below); an explicit `-ports` overrides it |
| `-port-timeout` | `1s` | Per-port connect timeout |
| `-format` | `table` | Output format: `table`, `json`, or `csv` |
| `-ignore-isolation` | off | Scan even if the network answers ARP for every address (see below) |
| `-version` | | Print version and exit |

## Isolated networks

Guest SSIDs and client-isolated wireless proxy-ARP every address to the gateway
so clients cannot reach each other. On such a network *every* address answers,
and a naive ARP sweep reports a full subnet of devices that do not exist.

Before scanning, `ais` probes a few randomly chosen addresses. If they all
answer with the same MAC, it refuses to run:

```
refusing to scan 172.16.0.0/24: every probed address answered with the same MAC
(44:12:44:c6:89:2c), so this network is answering ARP on behalf of hosts that do
not exist (guest or client-isolated Wi-Fi). Any result here would be fabricated.
Pass -ignore-isolation to scan anyway.
```

This matters most for roaming laptops: a scheduled scan that happens to run on
hotel or guest Wi-Fi would otherwise record a fabricated subnet. Real hosts have
distinct MACs, so a busy office subnet does not trip the check. `-ignore-isolation`
scans anyway and sets `"network_isolated": true` in the JSON report.

## Output

The results go to **stdout** and progress/status to **stderr**, so piping stdout
to a file or a parser yields clean data in every format.

### Ports: `-` vs `?`

In the table, the `OPEN PORTS` column distinguishes two cases that must never be
confused in an audit:

- `-` means the host **was** port-scanned and nothing was open.
- `?` means the ports were **never probed**, either because port scanning was
  disabled (`-ports ""`) or because the scan was cut short before reaching this
  host. In JSON and CSV this is the `ports_scanned` field.

An interrupted scan makes every connection fail instantly, which is
indistinguishable from a closed port, so a partial run reports `?` rather than
claiming the host is clean.

### Incomplete scans

If the scan does not cover the whole range (usually because `-timeout` expired),
`ais` still writes everything it collected, then reports the shortfall on stderr
and **exits 1**:

```
done: 28 host(s) responded across 108 of 254 addresses
scan incomplete: probed 108 of 254 addresses before the 6s timeout expired; results above are partial
```

In JSON this is the top-level `"complete": false`. Treat an incomplete report as
a partial sample, never as a full picture of the subnet.

Note that `-timeout` is not a hard bound. `SendARP` is a blocking call that does
not observe cancellation, so in-flight probes run to completion and the process
can overshoot the deadline by several seconds.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed over the whole range |
| `1` | Scan failed, or completed only partially (see stderr) |
| `2` | Bad command line |

An isolated network (above) exits `1` without writing a report.

### JSON

```json
{
  "scanned_at": "2026-09-18T14:30:12Z",
  "range": "192.168.20.8/29",
  "addresses_total": 6,
  "addresses_probed": 6,
  "network_isolated": false,
  "hosts": [
    {
      "ip": "192.168.20.10",
      "hostname": "ATNETPLUSDC1",
      "mac": "00:0c:29:34:36:83",
      "manufacturer": "VMware, Inc.",
      "open_ports": [445, 3389],
      "ports_scanned": true
    }
  ],
  "complete": true
}
```

### CSV

Columns are `ip,hostname,mac,manufacturer,open_ports,ports_scanned`. Open ports
are space-separated within their field so the value needs no quoting. CSV
carries host rows only; scan metadata is on stderr and in the exit code.

## Port sets

The `-audit` preset scans remote-access, file-sharing, printing, and database
ports in addition to web/admin panels:
`21,22,23,80,139,443,445,1433,3306,3389,5432,5900,5985,5986,6379,8006,8080,8081,8443,8843,8880,8888,9000,9100,10000,27017`
(FTP, SSH, Telnet, NetBIOS, SMB, MSSQL, MySQL, RDP, PostgreSQL, VNC, WinRM,
Redis, Proxmox, UniFi, Portainer, JetDirect printing, Webmin, MongoDB).

Examples:

```powershell
# Auto-detect and scan the local subnet
ais.exe

# Scan a specific range
ais.exe -range 192.168.1.0/24

# Faster/quieter for large scans, capturing the table to a file
ais.exe -range 10.0.0.0/24 -workers 100 -no-resolve > hosts.txt

# Full security-audit port set (remote access, file sharing, databases, ...)
ais.exe -range 192.168.1.0/24 -audit

# Audit a custom set of ports (an explicit -ports overrides -audit)
ais.exe -range 192.168.1.0/24 -ports 80,443,8080,8443,8006,10000

# Inventory only, skip the port scan
ais.exe -ports ""

# Machine-readable output for an RMM component or a UDF
ais.exe -audit -format json > scan.json

# CSV for a spreadsheet or a database import
ais.exe -format csv > hosts.csv
```

Ranges larger than a `/16` (65,536 addresses) are rejected as a safety guard, and
`-workers` is capped at 512: each worker parks in a blocking `SendARP` call,
which costs an OS thread.

When no `-range` is given, `ais` scans the subnet of the interface carrying the
default route, so a machine with Hyper-V, WSL, VPN, or both Wi-Fi and Ethernet
attached scans the network it actually lives on.

## Building

```powershell
go build -o ais.exe ./cmd/ais
```

To stamp a version into the binary (`ais -version`):

```powershell
go build -ldflags "-X github.com/xBen-Harveyx/average-ip-scanner/internal/config.Version=1.0.0" -o ais.exe ./cmd/ais
```

The tool targets Windows. It compiles on other platforms (for `go test`) but
`SendARP` is a no-op there, so scans return no hosts.

## Development

```powershell
go test ./...
```

### Regenerating the embedded OUI database

`internal/oui/oui.csv` is a two-column (`PREFIX,Vendor`) trim of the IEEE OUI
registry, embedded via `go:embed`. To refresh it:

```sh
curl -sSL -o oui_raw.csv https://standards-oui.ieee.org/oui/oui.csv
go run scripts/gen_oui.go oui_raw.csv internal/oui/oui.csv
```

(`scripts/gen_oui.go` reads the IEEE `Assignment` and `Organization Name`
columns and writes the trimmed, sorted CSV.)
