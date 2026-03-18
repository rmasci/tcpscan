package types

import (
	"crypto/x509"
	"time"
)

type PortStatus string

const (
	StatusOpen     PortStatus = "Open"
	StatusClosed   PortStatus = "Closed"
	StatusFiltered PortStatus = "Filtered"
)

type Config struct {
	Verbose      bool
	Debug        bool
	SSLCheck     bool
	DNSCheck     bool
	ICMPCheck    bool
	ICMPOnly     bool
	ShowOpen     bool
	ShowClosed   bool
	NoFormat     bool
	Protocol     string
	Timeout      time.Duration
	Comment      string
	OutputFormat string
	ExcelFile    string
	RootCAs      *x509.CertPool
	// New features
	Verbosity    int // 0=silent, 1=hints (quick), 2=detailed explanations
	ShowHints    bool
	Explain      bool
	Samples      int
	CheckPreset  string
	StatusLabels StatusLabels
}

type StatusLabels struct {
	Open     string
	Closed   string
	Filtered string
}

func DefaultStatusLabels() StatusLabels {
	return StatusLabels{
		Open:     "Open",
		Closed:   "Closed",
		Filtered: "Filtered",
	}
}

type ScanTarget struct {
	Address string
	Port    string
	Index   int
}

type ScanResult struct {
	Index      int
	Address    string
	Port       string
	Status     PortStatus
	TCPTime    time.Duration
	ICMPTime   time.Duration
	DNSTime    time.Duration
	SSLStatus  string
	ICMPFailed bool
	DNSFailed  bool
}

func (r *ScanResult) ToCSV() string {
	return ""
}

type ScanStats struct {
	Open     int
	Closed   int
	Filtered int
	Total    int
}
