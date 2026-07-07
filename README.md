# average-ip-scanner (`ais`)

A small AdvancedIPScanner-style CLI for Windows. Run it on a machine connected
to a network and it prints a table of live hosts on the **local subnet** with
their hostname, IP, MAC address, hardware manufacturer, and any open web ports.

The open-port check is a lightweight TCP connect scan of live hosts, aimed at
surfacing exposed web interfaces (router/admin panels, IoT device UIs) that may
need to be locked down.

It is built to run non-interactively through an RMM tool:

- Single self-contained binary (the OUI vendor database is embedded).
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
| `-progress` | `2s` | Interval between progress lines on stderr |
| `-no-resolve` | off | Skip reverse-DNS hostname lookups |
| `-ports` | `80,443,8000,8080,8443,8888` | Comma-separated TCP ports to check on live hosts; empty (`-ports ""`) disables port scanning |
| `-audit` | off | Use a broader security-audit port set instead of the web default (see below); an explicit `-ports` overrides it |
| `-port-timeout` | `1s` | Per-port connect timeout |

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
```

Ranges larger than a `/16` (65,536 addresses) are rejected as a safety guard.

## Building

```powershell
go build -o ais.exe ./cmd/ais
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
