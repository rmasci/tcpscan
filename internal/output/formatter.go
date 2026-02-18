package output

import (
	"fmt"
	"strings"
	"time"

	"github.com/rmasci/tcpscan/internal/types"
	"github.com/rmasci/gotabulate"
	"github.com/xuri/excelize/v2"
)

type Formatter struct {
	config *types.Config
}

func New(config *types.Config) *Formatter {
	return &Formatter{
		config: config,
	}
}

func (f *Formatter) Format(results []*types.ScanResult, format string) (string, error) {
	switch format {
	case "grid", "gridt":
		return f.formatGrid(results, "grid"), nil
	case "tab":
		return f.formatGrid(results, "tab"), nil
	case "csv":
		return f.formatCSV(results, ","), nil
	case "text":
		return f.formatCSV(results, " "), nil
	default:
		return f.formatGrid(results, "grid"), nil
	}
}

func (f *Formatter) formatGrid(results []*types.ScanResult, renderType string) string {
	if len(results) == 0 {
		return "No results to display"
	}

	headers := f.buildHeaders()
	// Pre-allocate capacity: header + all results
	rows := make([][]string, 1, len(results)+1)
	rows[0] = headers

	for _, result := range results {
		if result == nil {
			continue
		}
		row := f.buildRow(result)
		rows = append(rows, row)
	}

	if len(rows) <= 1 {
		return "Returned 0 results"
	}

	gridulate := gotabulate.Create(rows)
	gridulate.SetWrapStrings(false)
	return gridulate.Render(renderType)
}

func (f *Formatter) formatCSV(results []*types.ScanResult, delimiter string) string {
	var builder strings.Builder

	if delimiter != " " {
		headers := f.buildHeaders()
		builder.WriteString(strings.Join(headers, delimiter))
		builder.WriteString("\n")
	}

	for _, result := range results {
		if result == nil {
			continue
		}
		row := f.buildRow(result)
		builder.WriteString(strings.Join(row, delimiter))
		builder.WriteString("\n")
	}

	return builder.String()
}

func (f *Formatter) FormatExcel(results []*types.ScanResult, filename string) error {
	if filename == "" {
		filename = fmt.Sprintf("tcpscan-%s.xlsx", time.Now().Format("20060102-150405"))
	}

	xlsx := excelize.NewFile()
	defer xlsx.Close()

	sheetName := "Sheet1"
	xlsx.NewSheet(sheetName)

	headers := f.buildHeaders()
	for i, header := range headers {
		col, _ := excelize.ColumnNumberToName(i + 1)
		cell := fmt.Sprintf("%s1", col)
		xlsx.SetCellValue(sheetName, cell, header)
	}

	rowNum := 2
	for _, result := range results {
		if result == nil {
			continue
		}
		row := f.buildRow(result)
		for i, value := range row {
			col, _ := excelize.ColumnNumberToName(i + 1)
			cell := fmt.Sprintf("%s%d", col, rowNum)
			xlsx.SetCellValue(sheetName, cell, value)
		}
		rowNum++
	}

	if err := xlsx.SaveAs(filename); err != nil {
		return fmt.Errorf("failed to save Excel file: %w", err)
	}

	fmt.Printf("Wrote %d rows to %s\n", rowNum-2, filename)
	return nil
}

func (f *Formatter) buildHeaders() []string {
	if f.config.ICMPOnly {
		headers := []string{f.config.Comment}
		if f.config.ICMPCheck {
			headers = append(headers, "ICMP")
		}
		return headers
	}

	headers := []string{f.config.Comment, "Port", "Status", "TCP"}

	if f.config.ICMPCheck {
		headers = append(headers, "ICMP")
	}
	if f.config.DNSCheck {
		headers = append(headers, "NSLookup")
	}
	if f.config.SSLCheck {
		headers = append(headers, "SSL")
	}

	return headers
}

func (f *Formatter) buildRow(result *types.ScanResult) []string {
	if f.config.ICMPOnly {
		if f.config.ICMPCheck {
			return []string{result.Address, f.formatDuration(result.ICMPTime, result.ICMPFailed)}
		}
		return []string{result.Address}
	}

	// Pre-calculate capacity to avoid reallocation
	cap := 4
	if f.config.ICMPCheck {
		cap++
	}
	if f.config.DNSCheck {
		cap++
	}
	if f.config.SSLCheck {
		cap++
	}

	row := make([]string, 0, cap)
	row = append(row,
		result.Address,
		result.Port,
		string(result.Status),
		f.formatDuration(result.TCPTime, false),
	)

	if f.config.ICMPCheck {
		row = append(row, f.formatDuration(result.ICMPTime, result.ICMPFailed))
	}
	if f.config.DNSCheck {
		row = append(row, f.formatDuration(result.DNSTime, result.DNSFailed))
	}
	if f.config.SSLCheck {
		row = append(row, result.SSLStatus)
	}

	return row
}

func (f *Formatter) formatDuration(d time.Duration, failed bool) string {
	if failed {
		return "Failed"
	}

	if d == 0 {
		return "0"
	}

	if f.config.NoFormat {
		microseconds := float64(d.Nanoseconds()) / 1000.0
		return fmt.Sprintf("%.2f", microseconds)
	}

	// Direct conversion based on duration magnitude - faster than string parsing
	ns := d.Nanoseconds()
	switch {
	case ns < 1000: // nanoseconds
		return fmt.Sprintf("%.2fns ", float64(ns))
	case ns < 1000000: // microseconds
		return fmt.Sprintf("%.2fµs ", float64(ns)/1000.0)
	case ns < 1000000000: // milliseconds
		return fmt.Sprintf("%.2fms ", float64(ns)/1000000.0)
	default: // seconds
		return fmt.Sprintf("%.2fs  ", float64(ns)/1000000000.0)
	}
}

func (f *Formatter) CalculateStats(results []*types.ScanResult) types.ScanStats {
	stats := types.ScanStats{
		Total: len(results),
	}

	for _, result := range results {
		if result == nil {
			continue
		}
		switch result.Status {
		case types.StatusOpen:
			stats.Open++
		case types.StatusClosed:
			stats.Closed++
		case types.StatusFiltered:
			stats.Filtered++
		}
	}

	return stats
}

func (f *Formatter) PrintStats(stats types.ScanStats) {
	fmt.Printf("%s: %d, %s: %d, %s: %d\n",
		f.config.StatusLabels.Open, stats.Open,
		f.config.StatusLabels.Closed, stats.Closed,
		f.config.StatusLabels.Filtered, stats.Filtered)
}
