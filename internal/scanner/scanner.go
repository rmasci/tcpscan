package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/rmasci/tcpscan/internal/types"
)

func (s *Scanner) ScanTarget(ctx context.Context, target types.ScanTarget) (*types.ScanResult, error) {
	result := &types.ScanResult{
		Index:   target.Index,
		Address: target.Address,
		Port:    target.Port,
	}

	if s.config.DNSCheck {
		host := target.Address
		ipAddr, dnsTime, err := s.performDNSLookup(host)
		if err != nil {
			result.DNSFailed = true
		} else {
			result.Address = ipAddr
			result.DNSTime = dnsTime
		}
	}

	if s.config.ICMPCheck || s.config.ICMPOnly {
		icmpTime, err := s.performICMPCheck(ctx, result.Address)
		if err != nil {
			result.ICMPFailed = true
		} else {
			result.ICMPTime = icmpTime
		}
	}

	if !s.config.ICMPOnly {
		status, tcpTime, sslStatus, err := s.performTCPCheck(ctx, target.Address, target.Port)
		if err != nil {
			return nil, err
		}
		result.Status = status
		result.TCPTime = tcpTime
		result.SSLStatus = sslStatus
	}

	return result, nil
}

func (s *Scanner) checkSSL(conn net.Conn, host string) string {
	config := tls.Config{
		ServerName:         host,
		InsecureSkipVerify: false,
		RootCAs:            s.config.RootCAs,
	}

	tlsConn := tls.Client(conn, &config)
	defer tlsConn.Close()

	_, err := tlsConn.Read(nil)
	if err != nil {
		return "Failed"
	}

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return "No certificates"
	}

	cert := state.PeerCertificates[0]
	daysToExp := int((cert.NotAfter.Unix() - time.Now().Unix()) / 86400)

	var version string
	switch cert.Version {
	case 3:
		version = "TLS v1.2"
	case 2:
		version = "TLS v1.1"
	case 1:
		version = "TLS v1.0"
	case 0:
		version = "SSL v3"
	default:
		version = "TLS ?"
	}

	return fmt.Sprintf("%v / OK: %v days", version, daysToExp)
}

func (s *Scanner) performDNSLookup(host string) (string, time.Duration, error) {
	if strings.Contains(host, ":") {
		return host, 0, nil
	}

	if net.ParseIP(host) != nil {
		return host, 0, nil
	}

	startTime := time.Now()
	addrs, err := net.LookupHost(host)
	if err != nil {
		return host, 0, err
	}

	return addrs[0], time.Since(startTime), nil
}
