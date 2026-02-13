package parser

import (
	"bufio"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/rmasci/tcpscan/internal/types"
)

func ParseTargets(addresses []string, portSpec string) ([]types.ScanTarget, error) {
	ports, err := ParsePorts(portSpec)
	if err != nil {
		return nil, err
	}

	var targets []types.ScanTarget
	index := 0

	for _, port := range ports {
		for _, addr := range addresses {
			parsedTargets, err := parseAddress(addr, port)
			if err != nil {
				return nil, err
			}
			for _, target := range parsedTargets {
				target.Index = index
				targets = append(targets, target)
				index++
			}
		}
	}

	return removeDuplicateTargets(targets), nil
}

func ParseTargetsFromFile(filename, portSpec string) ([]types.ScanTarget, error) {
	addresses, err := readAddressesFromFile(filename)
	if err != nil {
		return nil, err
	}
	return ParseTargets(addresses, portSpec)
}

func readAddressesFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %w", filename, err)
	}
	defer file.Close()

	var addresses []string
	scanner := bufio.NewScanner(file)
	commentBlock := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "/*") {
			commentBlock = true
			continue
		}
		if strings.Contains(line, "*/") {
			commentBlock = false
			continue
		}
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") || commentBlock {
			continue
		}

		addresses = append(addresses, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	return addresses, nil
}

func parseAddress(addr, port string) ([]types.ScanTarget, error) {
	if strings.Count(addr, ":") >= 3 {
		return []types.ScanTarget{{
			Address: addr,
			Port:    port,
		}}, nil
	}

	if !strings.Contains(addr, "://") {
		addr = "tcpscan://" + addr
	}

	parsedURL, err := url.Parse(addr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse address %s: %w", addr, err)
	}

	urlPort := parsedURL.Port()
	if port == "noport" && urlPort == "" {
		port = LookupPort(parsedURL.Scheme)
	} else if port != "noport" && urlPort == "" {
		parsedURL.Host = parsedURL.Host + ":" + port
	} else if port != "noport" && urlPort != "" {
		host := strings.Split(parsedURL.Host, ":")[0]
		return []types.ScanTarget{{
			Address: host,
			Port:    port,
		}}, nil
	}

	if parsedURL.Port() == "" {
		parsedURL.Host = parsedURL.Host + ":22"
	}

	if _, err := strconv.Atoi(parsedURL.Port()); err != nil {
		return nil, fmt.Errorf("invalid port in %s: %w", addr, err)
	}

	cidr := parsedURL.RequestURI()
	if cidr == "" {
		cidr = "/32"
	} else {
		parts := strings.Split(cidr, "/")
		if len(parts) > 1 {
			slash, err := strconv.Atoi(parts[1])
			if err != nil || slash > 32 {
				cidr = "/32"
			}
		} else {
			cidr = "/32"
		}
	}

	ip, ipnet, err := net.ParseCIDR(parsedURL.Hostname() + cidr)
	if err != nil {
		return []types.ScanTarget{{
			Address: parsedURL.Hostname(),
			Port:    parsedURL.Port(),
		}}, nil
	}

	var targets []types.ScanTarget
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incrementIP(ip) {
		targets = append(targets, types.ScanTarget{
			Address: ip.String(),
			Port:    parsedURL.Port(),
		})
	}

	return targets, nil
}

func ParsePorts(portSpec string) ([]string, error) {
	if portSpec == "noport" {
		return []string{"noport"}, nil
	}

	var ports []string
	for _, p := range strings.Split(portSpec, ",") {
		if strings.Contains(p, "-") {
			rangePorts, err := parsePortRange(p)
			if err != nil {
				return nil, err
			}
			ports = append(ports, rangePorts...)
		} else {
			ports = append(ports, p)
		}
	}

	return ports, nil
}

func parsePortRange(rangeSpec string) ([]string, error) {
	parts := strings.Split(rangeSpec, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid port range: %s", rangeSpec)
	}

	from, err := strconv.Atoi(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid start port in range %s: %w", rangeSpec, err)
	}

	to, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid end port in range %s: %w", rangeSpec, err)
	}

	if to < from {
		return nil, fmt.Errorf("invalid port range %s: end port must be >= start port", rangeSpec)
	}

	var ports []string
	for i := from; i <= to; i++ {
		ports = append(ports, strconv.Itoa(i))
	}

	return ports, nil
}

func LookupPort(scheme string) string {
	if _, err := strconv.Atoi(scheme); err == nil {
		return scheme
	}

	portMap := map[string]string{
		"dns":     "53",
		"mail":    "25",
		"scp":     "22",
		"sftp":    "22",
		"rsync":   "22",
		"pcep":    "4189",
		"rdp":     "3389",
		"tcpscan": "22",
	}

	if port, ok := portMap[strings.ToLower(scheme)]; ok {
		return port
	}

	port, err := net.LookupPort("tcp", scheme)
	if err != nil {
		return "22"
	}

	return strconv.Itoa(port)
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func removeDuplicateTargets(targets []types.ScanTarget) []types.ScanTarget {
	seen := make(map[string]bool)
	var result []types.ScanTarget

	for _, target := range targets {
		key := target.Address + ":" + target.Port
		if !seen[key] {
			seen[key] = true
			result = append(result, target)
		}
	}

	return result
}
