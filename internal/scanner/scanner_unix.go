//go:build !windows

package scanner

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/rmasci/tcpscan/internal/types"
	tcp "github.com/tevino/tcp-shaker"
)

type Scanner struct {
	config     *types.Config
	tcpChecker *tcp.Checker
	dialer     *net.Dialer
}

func New(config *types.Config) *Scanner {
	checker := tcp.NewChecker()

	// Start the checker loop in background
	ctx := context.Background()
	go func() {
		if err := checker.CheckingLoop(ctx); err != nil {
			if config.Debug {
				fmt.Println("TCP checker loop stopped:", err)
			}
		}
	}()

	// Wait for checker to be ready
	<-checker.WaitReady()

	return &Scanner{
		config:     config,
		tcpChecker: checker,
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

	if s.config.Protocol != "tcp" || s.config.SSLCheck {
		conn, err = s.dialer.DialContext(ctx, s.config.Protocol, target)

		if err == nil {
			defer conn.Close()
			status = types.StatusOpen
		} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			status = types.StatusFiltered
		} else {
			status = types.StatusClosed
		}
	} else {
		status = s.tcpCheckerFast(target)
	}

	tcpTime := time.Since(startTime)

	if status == types.StatusOpen && s.config.SSLCheck && conn != nil {
		sslStatus = s.checkSSL(conn, host)
	}

	return status, tcpTime, sslStatus, nil
}

func (s *Scanner) tcpCheckerFast(target string) types.PortStatus {
	err := s.tcpChecker.CheckAddr(target, s.config.Timeout)
	switch err {
	case tcp.ErrTimeout:
		return types.StatusFiltered
	case nil:
		return types.StatusOpen
	default:
		return types.StatusClosed
	}
}
