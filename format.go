/*-
 * ============LICENSE_START=======================================================
 * Author: Richard Masci
 * ================================================================================
 * Copyright (C) 2017 - 2020 AT&T Intellectual Property. All rights reserved.
 * ================================================================================
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ============LICENSE_END=========================================================
 */
package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/360EntSecGroup-Skylar/excelize"
	"github.com/rmasci/gotabulate"
)

func gridout(render string, lines []string, stats bool) string {
	//sort.Sort(sort.StringSlice(lines))
	var qout bool
	if render == "qout" {
		fmt.Printf("<pre>")
		render = "gridt"
		qout = true
	}
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
		if PBServer != "" {
			return fmt.Sprintln(gridulate.Render(render))
		} else {
			fmt.Println(gridulate.Render(render))
		}
	}
	if stats {
		printStats(Open, Closed, Filtered)
	}
	if qout {
		fmt.Printf("</pre>")
	}

	return ""
}

func csvout(lines []string, stats bool, delim string) string {
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
	if PBServer != "" {
		return bOut.String()
	}
	fmt.Printf(bOut.String())
	return ""
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

	for _, line := range lines {
		l := strings.Split(line, ",")
		if len(l) >= 4 {
			lineNumber++
			for i, t := range l[1:] {
				axis := fmt.Sprintf("%v%v", lineNumber, excelize.ToAlphaString(i))
				ctr := fmt.Sprintf("%s", t)
				xlsx.SetCellValue("Sheet1", axis, ctr)
			}
		}
	}
	//fmt.Println("Rows: ",i)
	xlsx.SaveAs(fname)
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
