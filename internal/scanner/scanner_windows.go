//go:build windows

package scanner

import (
	"context"
	"net"
	"time"

	"github.com/rmasci/tcpscan/internal/types"
)

type Scanner struct {
	config *types.Config
	dialer *net.Dialer
}

func New(config *types.Config) *Scanner {
	return &Scanner{
		config: config,
		dialer: &net.Dialer{
			Timeout: config.Timeout,
		},
	}
}

func (s *Scanner) performTCPCheck(ctx context.Context, host, port string) (types.PortStatus, time.Duration, string, error) {
	target := net.JoinHostPort(host, port)
	startTime := time.Now()

	var status types.PortStatus
	var conn net.Conn
	var err error
	sslStatus := "N/A"

	conn, err = s.dialer.DialContext(ctx, s.config.Protocol, target)

	if err == nil {
		defer conn.Close()
		status = types.StatusOpen
	} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		status = types.StatusFiltered
	} else {
		status = types.StatusClosed
	}

	tcpTime := time.Since(startTime)

	if status == types.StatusOpen && s.config.SSLCheck && conn != nil {
		sslStatus = s.checkSSL(conn, host)
	}

	return status, tcpTime, sslStatus, nil
}
