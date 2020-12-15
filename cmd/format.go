package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"codecloud.web.att.com/st_cloudutils/gotabulate"
	"github.com/360EntSecGroup-Skylar/excelize"
)

func gridout(render string, lines []string, stats bool) string {
	//sort.Sort(sort.StringSlice(lines))
	var Open, Closed, Filtered int
	lenLines := len(lines)
	sortLines := make([]string, lenLines)
	for _, l := range lines {
		indx := strings.Split(l, ",")[0]
		x, _ := strconv.Atoi(indx)
		sortLines[x] = l
	}
	var minLength int
	c1 := []string{comment, "Port", "Status", "TCP"}
	if icmpCk {
		c1 = append(c1, "ICMP")
	}
	if dnsCk {
		c1 = append(c1, "NSLookup")
	}
	if sslCheck {
		c1 = append(c1, "SSL")
	}
	masterStr := [][]string{}
	masterStr = append(masterStr, c1)
	minLength = 1
	for _, line := range sortLines {
		if line != "" {
			lineArray := strings.Split(line, ",")[1:]
			if stats {
				switch lineArray[2] {
				case openPort:
					Open++
				case closedPort:
					Closed++
				case filterPort:
					Filtered++
				}
			}
			masterStr = append(masterStr, lineArray)
		}

	}

	if len(masterStr) <= minLength {
		fmt.Println("Returned 0 results")
	} else {
		gridulate := gotabulate.Create(masterStr)
		gridulate.SetWrapStrings(false)
		gridulate.SetRemEmptyLines(true)
		return fmt.Sprintln(gridulate.Render(render))

	}
	if stats {
		printStats(Open, Closed, Filtered)
	}
	return ""
}
func jsonout(lines []string, format bool) string {
	//var Open, Closed, Filtered int
	// need to loop through each line and build a struct that can be json.Marshalled.

	type DataResult struct {
		Dur      string `json:"Dur"`
		Hostname string `json:"Hostname"`
		ICMPDur  string `json:"ICMPDur"`
		NSDur    string `json:"NSLookup"`
		Port     string `json:"Port"`
		Result   string `json:"Result"`
		SSLCk    string `json:"SSLCk"`
	}
	type Result struct {
		Results []DataResult `json:"Results"`
	}
	var allResult Result
	for _, l := range lines {
		// fc is field count.
		var fc int
		var lineRes DataResult
		lineArr := strings.Split(l, ",")[1:]
		lineRes.Hostname = lineArr[0]
		lineRes.Port = lineArr[1]
		lineRes.Result = lineArr[2]
		lineRes.Dur = lineArr[3]
		fc = 3
		if icmpCk {
			fc++
			lineRes.ICMPDur = lineArr[fc]
		}
		if dnsCk {
			fc++
			lineRes.NSDur = lineArr[fc]
		}
		if sslCheck {
			fc++
			lineRes.SSLCk = lineArr[fc]
		}
		allResult.Results = append(allResult.Results, lineRes)
	}
	outByte, err := json.Marshal(allResult)
	errorHandle(err, "JSON Marshal", true)
	if format {
		var out bytes.Buffer
		json.Indent(&out, outByte, "", "  ")
		return fmt.Sprintln(out.String())
	} else {
		return fmt.Sprintf("%s", outByte)
	}
	return ""
}

func csvout(lines []string, stats bool, delim string) {
	var Open, Closed, Filtered int
	var bOut strings.Builder

	if delim != " " {
		fmt.Fprintf(&bOut, "%v,Port,Status,SSL,TCP", comment)
		if icmpCk {
			fmt.Fprintf(&bOut, ",ICMP")
		}
		if dnsCk {
			fmt.Fprintf(&bOut, ",NSLookup")
		}
		if sslCheck {
			fmt.Fprintf(&bOut, ",SSL")
		}
		fmt.Fprintf(&bOut, "\n")
	}
	for _, line := range lines {
		lTmp := strings.Split(line, ",")[1:]

		if stats {
			switch lTmp[2] {
			case openPort:
				Open++
			case closedPort:
				Closed++
			case filterPort:
				Filtered++
			}
		}
		line = strings.Join(lTmp, delim)
		if line != "" {
			fmt.Fprintln(&bOut, line)
		}
	}
	if stats {
		printStats(Open, Closed, Filtered)
	}
	fmt.Printf(bOut.String())
	return
}

func excelout(lines []string, fname string) {
	if debug {
		fmt.Printf("Started Excel out\n")
	}
	var c1 []string
	c1Str := "blank," + comment + ",Port,Status,TCP"
	if icmpCk {
		c1Str = c1Str + ",ICMP"
	}
	if dnsCk {
		c1Str = c1Str + ",NSlookup"
	}
	if sslCheck {
		c1Str = c1Str + ",SSL"
	}
	c1 = []string{c1Str}
	lines = append(c1, lines...)
	if fname == "" {
		fmt.Printf("You must pass a file name to store the Excel in.\n")
		os.Exit(1)
	}
	xlsx := excelize.NewFile()
	xlsx.NewSheet("Sheet1")
	lineNumber := 0
	/// This is each row
	for _, line := range lines {
		l := strings.Split(line, ",")
		if len(l) >= 4 {
			lineNumber++
			// each cell in row
			for i, t := range l[1:] {

				cntn, err := excelize.ColumnNumberToName(i)
				if err != nil {
					continue
				}
				axis := fmt.Sprintf("%v%v", cntn, lineNumber)
				xlsx.SetCellValue("Sheet1", axis, t)
			}
		}
	}
	//fmt.Println("Rows: ",i)
	if err := xlsx.SaveAs(fname); err != nil {
		fmt.Println(err)
	}
	fmt.Printf("Wrote %v rows to %v\n", lineNumber, fname)
}

func formatDuration(tSince time.Duration) (tDuration string) {
	u := tSince.String()
	vi := fmt.Sprintf("%v", tSince.Nanoseconds())
	v, _ := strconv.ParseFloat(vi, 64)
	if nofmt {
		tDuration = fmt.Sprintf("%.2f\n", v/1000)
		tDuration = strings.TrimSpace(tDuration)
		return tDuration
	}
	switch {
	case strings.Contains(u, "ns"):
		if debug {
			fmt.Printf("%v nano\n", tSince)
		}
		fStr := strings.TrimRight(u, "ns")
		if f, err := strconv.ParseFloat(fStr, 64); err == nil {
			tDuration = fmt.Sprintf("%.2fns", f)
		}
	case strings.Contains(u, "µs"):
		if debug {
			fmt.Printf("%v micro\n", tSince)
		}
		fStr := strings.TrimRight(u, "µs")
		if f, err := strconv.ParseFloat(fStr, 64); err == nil {
			tDuration = fmt.Sprintf("%.2fµs", f)
		}
	case strings.Contains(u, "ms"):
		if debug {
			fmt.Printf("%v milli\n", tSince)
		}
		fStr := strings.TrimRight(u, "ms")
		if f, err := strconv.ParseFloat(fStr, 64); err == nil {
			tDuration = fmt.Sprintf("%.2fms", f)
		}
	default:
		if debug {
			fmt.Printf("%v default\n", u)
		}
		fStr := strings.TrimRight(u, "s")
		if f, err := strconv.ParseFloat(fStr, 64); err == nil {
			tDuration = fmt.Sprintf("%.2fs", f)
		}
	}
	return tDuration
}
func printStats(Open, Closed, Filtered int) {
	fmt.Printf("%v: %v, %v: %v, %v: %v\n", openPort, Open, closedPort, Closed, filterPort, Filtered)
}
