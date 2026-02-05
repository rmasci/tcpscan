# TCPScan

A fast, lightweight TCP port validation tool designed for verifying connectivity, not discovery.

## What is TCPScan?

TCPScan is a **validation tool** built to quickly verify that known systems have expected ports open. Unlike comprehensive scanning tools like nmap or netcat, TCPScan focuses on:

- **Speed** - Faster than nmap for targeted checks
- **Simplicity** - Easy syntax, straightforward usage
- **Safety** - Limited to 2048 hosts/ports per scan to prevent misuse
- **Validation over Discovery** - Verify what you know should exist, not discover exploits

### Key Features

- ✅ TCP port connectivity checks
- ✅ SSL certificate validation
- ✅ DNS lookup timing
- ✅ ICMP ping checks
- ✅ Multiple output formats (Grid, CSV, Excel, Text)
- ✅ Subnet scanning (CIDR notation)
- ✅ Port range scanning
- ✅ File and pipe input support
- ✅ Cross-platform (Linux, macOS, Windows, BSD, Solaris)

### User-Friendly Features (New!)

- 💡 **Smart Diagnostic Hints** - Automatic suggestions when connections fail
- 📖 **Plain English Explanations** - Understand what results mean with `--explain`
- 🎯 **Service Presets** - Use `--check web` instead of remembering port numbers
- 📊 **Connection Quality Metrics** - Test reliability with `--samples N`

### Use Cases

- Verify database connectivity before deployment
- Check REST API endpoints are accessible
- Validate firewall rules
- Troubleshoot network connectivity issues
- Generate connectivity reports for documentation
- Disaster recovery validation

## Installation

### From GitHub Releases (Recommended)

Download the latest binary for your platform:

```bash
# Visit the releases page
https://github.com/rmasci/tcpscan/releases

# Or use curl/wget (example for macOS)
curl -L https://github.com/rmasci/tcpscan/releases/latest/download/tcpscan-mac -o tcpscan
chmod +x tcpscan
sudo mv tcpscan /usr/local/bin/
```

### Available Binaries

- **Linux AMD64**: `tcpscan-l64`
- **Linux ARM64**: `tcpscan-la64`
- **macOS Intel**: `tcpscan-mac`
- **macOS Apple Silicon**: `tcpscan-mac-arm`
- **Windows**: `tcpscan-w64.exe`
- **Raspberry Pi**: `tcpscan-pi`
- **BSD variants**: `tcpscan-ob64`, `tcpscan-net64`, `tcpscan-free64`

### Build from Source

```bash
git clone https://github.com/rmasci/tcpscan.git
cd tcpscan
make build
./build/tcpscan --version
```

### Creating a Release

To create a new release with automatic version tagging:

```bash
# Increments patch version, creates git tag, pushes tag, and builds all platforms
make release

# Example: v1.9.2 → v1.9.3
# - Creates and pushes git tag v1.9.3
# - Builds all platform binaries with new version
# - Binaries placed in ./release/ directory
```

Other build targets:
- `make` or `make all` - Build all platform binaries
- `make build` - Build for current platform only
- `make help` - Show all available targets

## Quick Start

### Basic Usage

```bash
# Check if port 22 is open
tcpscan example.com -p 22

# Check multiple ports
tcpscan example.com -p 22,80,443

# Scan a port range
tcpscan example.com -p 8000-8010

# Scan a subnet
tcpscan 192.168.1.0/24 -p 22
```

### Easy Troubleshooting (New!)

```bash
# Check web services (no need to remember ports!)
tcpscan example.com --check web

# Get plain-English explanations
tcpscan example.com -p 443 --explain

# Test connection reliability
tcpscan example.com -p 443 --samples 10

# Full diagnostic with hints
tcpscan problem-host.com --check web -i --explain
```

### Common Options

```bash
# SSL certificate check
tcpscan example.com -p 443 -s

# Include DNS lookup timing
tcpscan example.com -p 443 -d

# Include ICMP ping
tcpscan example.com -p 443 -i

# All checks together
tcpscan example.com -p 443 -s -d -i

# Only show open ports
tcpscan 192.168.1.0/24 -p 22 -o

# Adjust timeout for slow networks
tcpscan remote-host.com -p 443 -t 2s
```

### Input from Files

```bash
# File with one IP per line
tcpscan -f hosts.txt -p 22

# Pipe input
cat /etc/hosts | awk '{print $1}' | tcpscan -p 22
```

### Output Formats

```bash
# Default grid format (MySQL-like)
tcpscan example.com -p 443

# CSV output
tcpscan example.com -p 443 -O csv

# Plain text (for scripting)
tcpscan example.com -p 443 -O text

# Excel report
tcpscan -f hosts.txt -p 22,80,443 -e report.xlsx
```

## Example Output

### Basic Scan
```
+--------------+---------+-----------+-------------+
|      Address |    Port |    Status |         TCP |
+==============+=========+===========+=============+
|  example.com |     443 |      Open |    45.23ms  |
+--------------+---------+-----------+-------------+
```

### Full Validation (SSL + DNS + ICMP)
```
+-------------------+---------+-----------+------------+------------+-------------+---------------------------+
|           Address |    Port |    Status |        TCP |       ICMP |    NSLookup |                       SSL |
+===================+=========+===========+============+============+=============+===========================+
|    93.184.216.34  |     443 |      Open |    39.05ms |    66.06ms |     42.43ms |    TLS v1.2 / OK: 63 days |
+-------------------+---------+-----------+------------+------------+-------------+---------------------------+
```

## Status Meanings

- **Open** - TCP packet reached the system, port is listening
- **Closed** - TCP packet reached the system, port is not listening
- **Filtered** - TCP packet never reached the system (firewall/down)

If you see "Filtered", try adding `-i` to check if the host responds to ping. If ping works but the port is filtered, a firewall is likely blocking it.

## Scripting Examples

### Parse Output with awk
```bash
tcpscan 10.1.1.205 -p 22 -O text -i | awk '{print "Server is",$3,"Ping time",$5}'
# Output: Server is Open Ping time 13.99ms
```

### Check Multiple Hosts
```bash
for host in web1 web2 web3; do
    tcpscan $host -p 443 -O text
done
```

### Generate Report
```bash
tcpscan -f production-hosts.txt -p 22,80,443 -s -d -i -e connectivity-report.xlsx
```

## User-Friendly Troubleshooting Features

### Service Presets (--check)

No need to remember port numbers! Use service presets:

```bash
# Check web services (ports 80, 443 with SSL and DNS checks)
tcpscan example.com --check web

# Check database connectivity (MySQL, PostgreSQL, MSSQL, MongoDB, Redis)
tcpscan db.example.com --check database

# Check SSH access
tcpscan server.example.com --check ssh

# Check mail server
tcpscan mail.example.com --check mail
```

**Available presets:** `web`, `database`, `ssh`, `mail`, `dns`, `ldap`, `rdp`, `smb`

### Diagnostic Hints (Default)

TCPScan automatically shows helpful hints when connections fail:

```bash
tcpscan 127.0.0.1 -p 80

# Output includes:
127.0.0.1:80 - 💡 Host reachable but service not running. Check if service is started.
```

Disable with `--hints=false` if you don't want suggestions.

### Plain-English Explanations (--explain)

Get detailed, easy-to-understand explanations:

```bash
tcpscan example.com -p 443 --explain

# Shows:
# - What the result means in plain English
# - Possible causes of the issue
# - Specific next steps to try
```

### Connection Quality Testing (--samples)

Test connection reliability with multiple attempts:

```bash
# Run 10 connection attempts and show average
tcpscan example.com -p 443 --samples 10
```

Use this to:
- Detect intermittent connection issues
- Measure average latency
- Validate network improvements

### Real-World Examples

**"Website won't load"**
```bash
tcpscan example.com --check web --explain
```

**"Database is slow"**
```bash
tcpscan db.example.com --check database --samples 10
```

**"Sometimes can't connect"**
```bash
tcpscan server.example.com -p 22 --samples 20 -i --explain
```

## Advanced Features

### Subnet Calculator
```bash
tcpscan -C 192.168.1.0/24
```

### Service Name Resolution
```bash
# Use service names instead of port numbers
tcpscan ipp://10.1.1.1    # Looks up IPP port (631)
tcpscan https://example.com  # Uses port 443
```

### Timeout Adjustment
```bash
# Default is 500ms, adjust for slow/remote hosts
tcpscan remote-host.com -p 443 -t 2s
```

## Limitations

- **Maximum 2048 hosts/ports per scan** - This is a safety feature to prevent misuse
- **Not a discovery tool** - Designed for validation, not vulnerability scanning
- **No stealth scanning** - Uses standard TCP connections

## Getting Help

```bash
# Show version
tcpscan -v

# Show help
tcpscan -h

# Show extended usage
tcpscan -a
```

## Credits

TCPScan is built with Go and uses these excellent packages:

- [Excelize](https://github.com/xuri/excelize) - Excel file generation
- [GoTabulate](https://github.com/rmasci/gotabulate) - Table formatting
- [TCP-Shaker](https://github.com/tevino/tcp-shaker) - Fast TCP checking
- [IPSubnet](https://github.com/rmasci/ipsubnet) - Subnet calculations
- [PFlag](https://github.com/spf13/pflag) - POSIX-style flags

## License

See [LICENSE](LICENSE) file for details.

## Contributing

For technical documentation on building, modernization, and optimizations, see the [cmd/](cmd/) directory.
