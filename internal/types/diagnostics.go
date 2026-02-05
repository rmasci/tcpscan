package types

import "fmt"

type Diagnostic struct {
	Status      PortStatus
	Explanation string
	Suggestions []string
	NextSteps   []string
}

func GetDiagnostic(result *ScanResult, config *Config) Diagnostic {
	diag := Diagnostic{Status: result.Status}

	switch result.Status {
	case StatusOpen:
		diag.Explanation = "Connection successful! The port is open and accepting connections."
		if config.SSLCheck && result.SSLStatus != "" && result.SSLStatus != "N/A" {
			diag.Suggestions = append(diag.Suggestions, "✓ SSL certificate is valid")
		}
		if config.DNSCheck && !result.DNSFailed {
			diag.Suggestions = append(diag.Suggestions, "✓ DNS lookup successful")
		}
		if config.ICMPCheck && !result.ICMPFailed {
			diag.Suggestions = append(diag.Suggestions, "✓ Host responds to ping")
		}

	case StatusClosed:
		diag.Explanation = "The host is reachable, but nothing is listening on this port."
		diag.Suggestions = []string{
			"The service may not be running on the remote system",
			"The service may be configured to listen on a different port",
			"The service may have crashed or been stopped",
		}
		diag.NextSteps = []string{
			"Verify the service is started on the remote system",
			"Check the service configuration for the correct port",
			"Review service logs for errors",
		}
		if !config.ICMPCheck {
			diag.NextSteps = append(diag.NextSteps, fmt.Sprintf("Try with ping check: tcpscan %s -p %s -i", result.Address, result.Port))
		}

	case StatusFiltered:
		diag.Explanation = "The connection attempt timed out. The host may be down or a firewall is blocking access."
		diag.Suggestions = []string{
			"A firewall may be blocking the connection",
			"The host may be powered off or unreachable",
			"Network routing issues may prevent connectivity",
			"The port may be blocked at a router or switch",
		}
		diag.NextSteps = []string{
			"Check if the host is powered on and connected to the network",
			"Verify firewall rules allow traffic on this port",
			"Confirm the IP address or hostname is correct",
		}
		if !config.ICMPCheck {
			diag.NextSteps = append(diag.NextSteps, fmt.Sprintf("Try with ping check: tcpscan %s -p %s -i", result.Address, result.Port))
		} else if !result.ICMPFailed {
			diag.Suggestions = append(diag.Suggestions, "⚠ Host responds to ping but port is filtered - likely a firewall")
		}
	}

	return diag
}

func (d Diagnostic) String() string {
	output := fmt.Sprintf("\n%s\n", d.Explanation)
	
	if len(d.Suggestions) > 0 {
		output += "\nPossible causes:\n"
		for _, suggestion := range d.Suggestions {
			output += fmt.Sprintf("  • %s\n", suggestion)
		}
	}
	
	if len(d.NextSteps) > 0 {
		output += "\nNext steps:\n"
		for _, step := range d.NextSteps {
			output += fmt.Sprintf("  → %s\n", step)
		}
	}
	
	return output
}

func GetQuickHint(status PortStatus, icmpFailed bool, hasICMP bool) string {
	switch status {
	case StatusOpen:
		return "✓ Connection successful"
	case StatusClosed:
		return "💡 Host reachable but service not running. Check if service is started."
	case StatusFiltered:
		if hasICMP && !icmpFailed {
			return "💡 Host responds to ping but port filtered. Likely blocked by firewall."
		}
		return "💡 Connection timeout. Host may be down or blocked by firewall. Try: -i to check ping"
	default:
		return ""
	}
}
