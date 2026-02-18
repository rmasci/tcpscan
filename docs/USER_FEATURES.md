# User-Friendly Features for Non-Technical Users

TCPScan includes several features designed to help non-network engineers troubleshoot connectivity issues.

## Quick Diagnostic Hints (Default)

By default, TCPScan shows helpful hints when ports are not open:

```bash
tcpscan 127.0.0.1 -p 80,22

+--------------+---------+-----------+---------------+
|      Address |    Port |    Status |           TCP |
+==============+=========+===========+===============+
|    127.0.0.1 |      80 |    Closed |    334.00µs  |
+--------------+---------+-----------+---------------+
|    127.0.0.1 |      22 |      Open |    442.67µs  |
+--------------+---------+-----------+---------------+

127.0.0.1:80 - 💡 Host reachable but service not running. Check if service is started.
```

### Disable Hints

If you don't want hints, use `--hints=false`:

```bash
tcpscan example.com -p 443 --hints=false
```

## Detailed Explanations (--explain)

For detailed, plain-English explanations of what each result means:

```bash
tcpscan 127.0.0.1 -p 80 --explain

+--------------+---------+-----------+------------+
|      Address |    Port |    Status |        TCP |
+==============+=========+===========+============+
|    127.0.0.1 |      80 |    Closed |    1.05ms  |
+--------------+---------+-----------+------------+

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
127.0.0.1:80 - Closed

The host is reachable, but nothing is listening on this port.

Possible causes:
  • The service may not be running on the remote system
  • The service may be configured to listen on a different port
  • The service may have crashed or been stopped

Next steps:
  → Verify the service is started on the remote system
  → Check the service configuration for the correct port
  → Review service logs for errors
  → Try with ping check: tcpscan 127.0.0.1 -p 80 -i
```

### When to Use --explain

- **Learning**: Understanding what scan results mean
- **Troubleshooting**: Getting actionable next steps
- **Documentation**: Including explanations in reports

## Service Presets (--check)

Instead of remembering port numbers, use service presets:

### Available Presets

| Preset | Description | Ports Checked |
|--------|-------------|---------------|
| `web` | Web services | 80, 443 |
| `database` | Common databases | 3306, 5432, 1433, 27017, 6379 |
| `ssh` | SSH remote access | 22 |
| `mail` | Email services | 25, 587, 993, 995, 465 |
| `dns` | DNS servers | 53 |
| `ldap` | LDAP/Active Directory | 389, 636, 3268, 3269 |
| `rdp` | Remote Desktop | 3389 |
| `smb` | Windows file sharing | 445, 139 |

### Usage Examples

```bash
# Check web services (automatically checks 80, 443 with SSL and DNS)
tcpscan example.com --check web

# Check database connectivity
tcpscan db.example.com --check database

# Check SSH access
tcpscan server.example.com --check ssh

# Check mail server
tcpscan mail.example.com --check mail
```

### What Presets Do

Presets automatically:
- Set the correct ports for the service
- Enable appropriate checks (SSL, DNS, ICMP)
- Provide service-specific context

For example, `--check web` automatically:
- Checks ports 80 and 443
- Enables SSL certificate validation (`-s`)
- Enables DNS lookup (`-d`)

## Connection Quality Metrics (--samples)

Test connection reliability by running multiple checks:

```bash
# Run 10 connection attempts
tcpscan example.com -p 443 --samples 10
```

This will:
- Perform 10 separate connection attempts
- Calculate average latency
- Show more reliable timing information
- Help identify intermittent issues

### When to Use --samples

- **Intermittent Issues**: Connection sometimes works, sometimes doesn't
- **Performance Testing**: Measure average response time
- **Network Quality**: Check for latency variations
- **Before/After Comparisons**: Validate network improvements

### Example Output

```bash
tcpscan example.com -p 443 --samples 10

+--------------+---------+-----------+-------------+
|      Address |    Port |    Status |         TCP |
+==============+=========+===========+============+
|  example.com |     443 |      Open |    45.23ms  |  # Average of 10 samples
+--------------+---------+-----------+-------------+
```

## Combining Features

You can combine features for comprehensive troubleshooting:

```bash
# Full diagnostic check with explanations
tcpscan example.com --check web --explain

# Quality check with hints
tcpscan db.example.com --check database --samples 5

# Detailed troubleshooting
tcpscan problem-host.com -p 443 --samples 10 --explain -i -d -s
```

## Common Troubleshooting Scenarios

### Scenario 1: "Can't connect to website"

```bash
tcpscan example.com --check web --explain
```

This will:
- Check both HTTP (80) and HTTPS (443)
- Validate SSL certificates
- Check DNS resolution
- Provide explanations if anything fails

### Scenario 2: "Database connection is slow"

```bash
tcpscan db.example.com --check database --samples 10
```

This will:
- Check all common database ports
- Run 10 connection attempts
- Show average connection time
- Help identify if it's consistently slow or intermittent

### Scenario 3: "Sometimes can't reach server"

```bash
tcpscan server.example.com -p 22 --samples 20 -i --explain
```

This will:
- Run 20 connection attempts
- Include ping checks
- Provide detailed explanations
- Help identify intermittent network issues

### Scenario 4: "Not sure what's wrong"

```bash
tcpscan problem-host.com -p 443 -i -d -s --explain
```

This will:
- Check the port
- Test ping (ICMP)
- Check DNS resolution
- Validate SSL certificate
- Provide detailed explanations of any issues

## Understanding the Hints

### For "Open" Status
```
✓ Connection successful
```
Everything is working correctly.

### For "Closed" Status
```
💡 Host reachable but service not running. Check if service is started.
```

**What this means:**
- Your computer can reach the host
- But nothing is listening on that port

**What to do:**
1. Check if the service is running
2. Verify you're using the correct port
3. Check service configuration

### For "Filtered" Status
```
💡 Connection timeout. Host may be down or blocked by firewall. Try: -i to check ping
```

**What this means:**
- Connection attempt timed out
- Could be firewall, could be host down

**What to do:**
1. Try with `-i` to check if host responds to ping
2. If ping works but port filtered → firewall blocking
3. If ping fails → host may be down or unreachable

### For "Filtered" with Ping Success
```
💡 Host responds to ping but port filtered. Likely blocked by firewall.
```

**What this means:**
- Host is definitely up and reachable
- But the specific port is blocked

**What to do:**
1. Check firewall rules
2. Verify port is correct
3. Contact network administrator if needed

## Tips for Non-Technical Users

1. **Start with presets**: Use `--check web` instead of remembering port numbers
2. **Use --explain**: Get plain-English explanations of what's happening
3. **Add -i for more info**: Including ping helps narrow down issues
4. **Use --samples for flaky connections**: If it "sometimes works", try `--samples 10`
5. **Read the hints**: The automatic hints guide you to next steps

## Quick Reference

```bash
# Simple web check with explanation
tcpscan example.com --check web --explain

# Database connectivity with quality check
tcpscan db.example.com --check database --samples 5

# Full diagnostic
tcpscan host.example.com -p 443 -i -d -s --explain

# Intermittent issue investigation
tcpscan flaky-host.com -p 80 --samples 20 --explain
```

## Getting Help

If you're still stuck:

1. Run with `--explain` to get detailed information
2. Include `-i -d -s` for comprehensive checks
3. Use `--samples 10` if the issue is intermittent
4. Share the output with your network team

The tool is designed to give you the information needed to either fix the issue yourself or provide useful details to someone who can help.
