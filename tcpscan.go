/*-
 * ============LICENSE_START=======================================================
 * Author: Richard Masci
 * ================================================================================
 * Copyright (C) 2017 - 2020 AT&T Intellectual Property. All rights reserved.
 * ================================================================================
 * The MIT License (MIT)
 *
 * Copyright <year> AT&T Intellectual Property. All other rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software
 * and associated documentation files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
 * AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 * ============LICENSE_END=========================================================
 */

package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	flag "github.com/spf13/pflag"
)

// TODO: Break this into smaller files.
// TODO: Make type for scanning hosts:
/*
type scan struct {
		Port 	  string
		IP   	  string
        Host  	  string
		Protocol  string
		ICMP      time.Duration
		Scan      time.Duration
		SSL       string
}
*/
var (
	verb                             bool
	debug                            bool
	sslCheck                         bool
	dnsCk                            bool
	icmpCk                           bool
	showOpen                         bool
	rootCAs                          *x509.CertPool
	comment                          string
	openPort, closedPort, filterPort string
	proto                            string
	nofmt                            bool
	PBServer                         string
	exitstatus                       int
)

func main() {
	startTime := time.Now()
	var (
		scanAddr, ipaddr, lines []string
		i                       int
		goRoutine               []int
		scan, port, file        string
		timeout, outF, xlOut    string
		help, stats, calc       bool
		statComm                string
	)
	exitstatus = 0
	results := make(chan string)
	flag.StringVarP(&port, "port", "p", "noport", "Port to scan")
	flag.StringVarP(&proto, "protocol", "P", "tcp", "Protocol to use, tcp is default.")
	flag.BoolVarP(&showOpen, "open", "o", false, "Only show open ports.")
	flag.BoolVarP(&verb, "verbose", "v", false, "Verbose")
	flag.BoolVarP(&debug, "vv", "", false, "Very Verbose")
	flag.StringVarP(&comment, "comment", "c", "", "Add a comment. Replaces 'Address' in output header of table.")
	flag.StringVarP(&statComm, "sc", "", "", "Add a comment to the status field. Must be 3 fields comma separated. Default is \"Open,Closed,Filtered\".")
	flag.BoolVarP(&help, "help", "h", false, "help")
	flag.BoolVarP(&nofmt, "no-format", "x", false, "Do not format time output. Output will be in microseconds.")
	flag.StringVarP(&xlOut, "excel", "e", "", "Save output in Excel Format.")
	flag.BoolVarP(&sslCheck, "ssl", "s", false, "Check SSL Cert.")
	flag.BoolVarP(&dnsCk, "dns", "d", false, "Enable DNS Check")
	flag.BoolVarP(&icmpCk, "icmp", "i", false, "Enable ICMP Check")
	flag.BoolVarP(&calc, "calc", "C", false, "Subnet Calculator.  ex: tcpscan -c 10.1.1.0/24")
	flag.BoolVarP(&stats, "stats", "S", false, "Print Stats. Usefull when scanning more than one host.")
	flag.StringVarP(&outF, "output", "O", "gridt", "output: grid, gridt, text, csv, tab")
	flag.StringVarP(&timeout, "timeout", "t", "500ms", "Timeout value. 5s= 5 seconds, 5ms=5 milliseconds and so on (5ns, 5us).")
	flag.StringVarP(&file, "file", "f", "", "A filename containing a list of IP addresses to scan, separated by newlines.")
	flag.Parse()

	if help {
		flag.PrintDefaults()
		usage()
		os.Exit(0)
	}

	//set files.
	setFilesLimit()
	if comment == "" {
		comment = "Address"
	}
	{
		stComm := strings.Split(statComm, ",")
		if len(stComm) == 3 {
			openPort = stComm[0]
			closedPort = stComm[1]
			filterPort = stComm[2]
		} else {
			openPort = "Open"
			closedPort = "Closed"
			filterPort = "Filtered"
		}
	}

	if file == "" {
		ipaddr = flag.Args()
		if calc {
			subnetCalc(ipaddr[0])
			os.Exit(0)
		}
		// Look for info coming from STDIN:
		stat, _ := os.Stdin.Stat()
		if (stat.Mode()&os.ModeCharDevice) == 0 && len(ipaddr) == 0 {
			inBytes, _ := ioutil.ReadAll(os.Stdin)
			ipaddr = strings.Fields(string(inBytes))
		} else if len(ipaddr) == 0 {
			ipaddr = append(ipaddr, "127.0.0.1")
		}
		scanAddr = ipList(ipaddr, port)
	} else {
		scanAddr = fileList(file, port)
	}

	scanLen := len(scanAddr)
	if scanLen > 2048 {
		fmt.Printf("Sorry, you can't scan more than 2048 hosts / ports at a time. Hosts/Ports: %v\n", scanLen)
		os.Exit(1)
	} else if scanLen > 512 && timeout == "" {
		timeout = "3s"
	} else if scanLen > 256 && timeout == "" {
		timeout = "2s"
	}
	if timeout == "" {
		timeout = "5s"
	}
	// Set Root Certs for SSL
	if sslCheck {
		rootCert := digicertRoot()
		if runtime.GOOS != "windows" {
			rootCAs, _ = x509.SystemCertPool()

			if ok := rootCAs.AppendCertsFromPEM([]byte(rootCert)); !ok {
				if verb {
					fmt.Printf("Can't add certs from PEM")
				}
			}
		}
	}
	//fmt.Printf("Timeout: %v\n", timeout)
	timeOut, err := time.ParseDuration(timeout)
	errorHandle(err, "Parse Duration Timeout", true)

	if xlOut != "" {
		outF = "excel"
	}

	// This checks the timeout value specified so that the user can't have a timeout over 5 seconds.
	ckTimeOut := int64(timeOut) / int64(time.Second)
	if ckTimeOut > 10 {
		fmt.Printf("Specify a timeout less than or equal to 10 seconds.\n")
		os.Exit(1)
	}
	//errorHandle(err)
	if debug {
		fmt.Printf("Length of scanAddr:= %v\n", len(scanAddr))
	}
	// Remove Duplicates:
	scanAddr = removeDuplicates(scanAddr)
	for i, scan = range scanAddr {
		go scanPort(scan, timeOut, i, showOpen, sslCheck, results)
		goRoutine = append(goRoutine, i)
	}
	if verb {
		fmt.Printf("Go Routines launched: %v\n", i)
	}
	for _, goR := range goRoutine {
		//fmt.Printf(".")
		if verb {
			fmt.Printf("Waiting for.: %v ", goR)
		}
		r := <-results
		lines = append(lines, r)
		if verb {
			fmt.Printf("Recieved %v\n", goR)
		}

	}

	switch outF {
	case "qout":
		_ = gridout("qout", lines, stats)
	case "html":
		_ = gridout("html", lines, stats)
	case "grid":
		_ = gridout("grid", lines, stats)
	case "gridt":
		_ = gridout("gridt", lines, stats)
	case "tab":
		_ = gridout("tab", lines, stats)
	case "csv":
		_ = csvout(lines, stats, ",")
	case "excel":
		excelout(lines, xlOut)
	case "text":
		_ = csvout(lines, stats, " ")
	default:
		_ = gridout("grid", lines, stats)
	}
	if strings.Contains(outF, "grid") {
		tSince := time.Since(startTime)
		tDur := formatDuration(tSince)
		fmt.Printf("Scanned %v hosts/ports in %s.\n", len(scanAddr), tDur)
	}
	os.Exit(exitstatus)
}

func ipList(ipaddr []string, inPort string) (scanAddr []string) {
	ports := parsePorts(inPort)
	for _, port := range ports {
		for _, aURL := range ipaddr {
			if strings.Count(aURL, ":") >= 3 {
				if verb {
					fmt.Printf("ipv6?\n")
				}
				scanAddr = append(scanAddr, fmt.Sprintf("[%v]:%v", aURL, port))
				continue
			}
			if len(strings.Split(aURL, "://")) <= 1 {
				aURL = "tcpscan://" + aURL
				if verb {
					fmt.Println("Added tcpscan://")
				}
			}
			parsedURL, err := url.Parse(aURL)
			if err != nil {
				fmt.Printf("%v\n", err)
			}
			// ports...
			uPort := parsedURL.Port()
			if verb {
				fmt.Printf("uPort: %v\n", uPort)
			}
			if port == "noport" && uPort == "" {
				h := portLookup(parsedURL.Scheme)
				parsedURL.Host = parsedURL.Host + ":" + h
				if verb {
					fmt.Printf("Setting the host:port %v\n", parsedURL.Host)
				}
			} else if port != "noport" && uPort == "" {
				if verb {
					fmt.Printf("Configure the port, %v\n", port)
				}
				parsedURL.Host = parsedURL.Host + ":" + port
			} else if port != "noport" && uPort != "" {
				hst := strings.Split(parsedURL.Host, ":")[0]
				scanAddr = append(scanAddr, hst+":"+port)
			}
			// Next line is a failsafe. If nothing at this point is set, default to 22.

			if parsedURL.Port() == "" {
				if verb {
					fmt.Println("ParsedURL port was blank.")
				}
				parsedURL.Host = parsedURL.Host + ":22"
			}

			if verb {
				fmt.Printf("Host %v Port: %v\n", parsedURL.Host, parsedURL.Port())
			}
			_, err = strconv.Atoi(parsedURL.Port())
			errorHandle(err, "Port isn't valid", true)
			//Subnet...
			aURI := parsedURL.RequestURI()
			if aURI == "" {
				aURI = "/32"
			} else {
				tmpURI := strings.Split(aURI, "/")[1]
				slash, err := strconv.Atoi(tmpURI)
				if err != nil || slash > 32 {
					aURI = "/32"
				}
			}
			ip, ipnet, err := net.ParseCIDR(parsedURL.Hostname() + aURI)
			if err != nil {
				scanAddr = append(scanAddr, parsedURL.Host)
			} else {
				for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
					appendData := fmt.Sprintf("%v:%v", ip.String(), parsedURL.Port())
					scanAddr = append(scanAddr, appendData)
				}
			}
		}
	}
	if verb {
		fmt.Printf("List: %v\n", scanAddr)
	}
	return scanAddr
}

func fileList(file, port string) (scanAddr []string) {
	//ports := parsePorts(port)
	var ips []string
	ipFile, err := os.Open(file)
	_ = errorHandle(err, "Open File", true)
	defer ipFile.Close()
	scanner := bufio.NewScanner(ipFile)
	scanner.Split(bufio.ScanLines)
	commentBlock := false
	for scanner.Scan() {
		//fmt.Printf("Scanner: %v\n", scanner.Text())
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "/*") {
			commentBlock = true
			continue
		}
		if strings.Contains(line, "*/") {
			commentBlock = false
			continue
		}
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") || commentBlock == true {
			continue
		} else {
			ips = append(ips, line)
		}
	}
	if verb {
		fmt.Printf("ips %v\n", ips)
	}
	scanAddr = ipList(ips, port)
	return scanAddr
}

func errorHandle(e error, s string, exit bool) bool {
	if e != nil {
		// notice that we're using 1, so it will actually log the where
		// the error happened, 0 = this function, we don't want that.
		pc, fn, line, _ := runtime.Caller(1)
		//log.Printf("ERROR: %s\n", s)
		log.Printf("%s [error] in %s[%s:%d] %v", s, runtime.FuncForPC(pc).Name(), fn, line, e)
		if exit {
			os.Exit(1)
		} else {
			return true
		}
	}
	return false
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func parseCIDR(ipStr string) (ips []string) {
	if strings.Contains(ipStr, "://") {
		tmp := strings.Split(ipStr, "://")
		if tmp[0] != "tcpscan" {
			fmt.Printf("Dropping \"%v://\" from scan.\n", tmp[0])
		}
		ipStr = tmp[1]
	}

	ip, ipnet, err := net.ParseCIDR(ipStr)
	errorHandle(err, "Parse CIDR", true)
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	//strip first and last for network and broadcast
	cut := len(ips) - 1
	return ips[1:cut]
}

func parsePorts(port string) (ports []string) {
	if port == "nopass" {
		ports = append(ports, "nopass")
		return ports
	}
	for _, p := range strings.Split(port, ",") {
		if strings.Contains(p, "-") {
			pTmp := strings.Split(p, "-")
			fr, _ := strconv.Atoi(pTmp[0])
			to, _ := strconv.Atoi(pTmp[1])
			if to < fr {
				fmt.Printf("Invalid Entry: %s\n", p)
				os.Exit(1)
			}
			for i := fr; i <= to; i++ {
				prt := strconv.Itoa(i)
				ports = append(ports, prt)
			}
		} else {
			ports = append(ports, p)
		}
	}
	return ports
}

func portLookup(port string) string {
	_, err := strconv.Atoi(port)
	if err == nil {
		return port
	}
	switch strings.ToLower(port) {
	case "dns":
		return "53"
	case "mail":
		return "25"
	case "scp":
		return "22"
	case "sftp":
		return "22"
	case "rsync":
		return "22"
	case "pcep":
		return "4189"
	case "rdp":
		return "3389"
	case "tcpscan":
		return "22"
	default:
		ptmp, err := net.LookupPort(proto, port)
		errorHandle(err, "Invalid Port", true)
		return strconv.Itoa(ptmp)

	}
	return "22"
}

func scanPort(target string, timeOut time.Duration, index int, showOpen, sslCheck bool, results chan<- string) {
	var status, result, nsDur, host, icmpDur string
	icmpChan := make(chan string)
	tTmp := strings.Split(target, ":")
	if dnsCk {
		h := strings.Join(tTmp[0:len(tTmp)-1], ":")
		host, nsDur = nsLookup(h)
	} else {
		host = strings.Join(tTmp[0:len(tTmp)-1], ":")
		nsDur = "--"
	}
	port := tTmp[len(tTmp)-1]
	if verb {
		fmt.Printf("HOST: \"%v\", Target: \"%v\", NS: %v\n", host, target, nsDur)
	}
	if icmpCk {
		if runtime.GOOS == "windows" {
			go scanIPWindows(host, &timeOut, icmpChan)
		} else {
			go scanIPLinux(host, &timeOut, icmpChan)
		}
	}
	status = closedPort

	tStart := time.Now()
	sslStatus := "N/A"
	var connTCP net.Conn
	var errTCP error
	if proto != "tcp" || sslCheck || runtime.GOOS == "windows" {
		connTCP, errTCP = net.DialTimeout(proto, target, timeOut)

		if errTCP == nil {
			defer connTCP.Close()
			status = openPort
		}
		if errTCP, ok := errTCP.(net.Error); ok && errTCP.Timeout() {
			status = filterPort
		}
	} else {
		status = tcpChecker(target, timeOut)
	}
	tSince := time.Since(tStart)
	if verb || debug {
		fmt.Printf("%v Status target: %v - %v: %v\n", index, target, status, tSince)
	}
	tDur := formatDuration(tSince)

	if status == openPort && sslCheck {
		sslHost := strings.Split(tTmp[0], ":")[0]
		// Configure tls to look at domainName
		config := tls.Config{
			ServerName:         sslHost,
			InsecureSkipVerify: false,
			RootCAs:            rootCAs,
		}
		// Connect to tls
		conn := tls.Client(connTCP, &config)
		defer conn.Close()
		// Handshake with TLS to get cert
		_, hsErr := conn.Read(nil)
		if hsErr != nil {
			fmt.Printf("SSL Failed: %v\n", hsErr)
			sslStatus = fmt.Sprintf("Failed -1")
		} else {
			ver := "TLS ?"
			state := conn.ConnectionState()
			pc := *state.PeerCertificates[0]
			daysToExp := ((pc.NotAfter.Unix() - time.Now().Unix()) / 86400)
			switch pc.Version {
			case 3:
				ver = fmt.Sprintf("TLS v1.2")
			case 2:
				ver = fmt.Sprintf("TLS v1.1")
			case 1:
				ver = fmt.Sprintf("TLS v1.0")
			case 0:
				ver = fmt.Sprintf("SSL v3")
			}
			sslStatus = fmt.Sprintf("%v / OK: %v days", ver, daysToExp)
		}

	} else if status == closedPort || status == filterPort {
		sslStatus = "Failed -2"
		if showOpen {
			results <- ""
			return
		}
		exitstatus = 1
	}

	if icmpDur == "" {
		icmpDur = "0"
	}
	// print Results
	host = strings.TrimLeft(host, "[")
	host = strings.TrimRight(host, "]")
	result = fmt.Sprintf("%v,%s,%s,%s,%v", index, host, port, status, tDur)
	if verb {
		//fmt.Printf("Result: %v\n", result)
	}
	if icmpCk {
		icmpDur := <-icmpChan
		result = fmt.Sprintf("%s,%s", result, icmpDur)
	}
	if dnsCk {
		result = fmt.Sprintf("%s,%s", result, nsDur)
	}
	if sslCheck {
		result = fmt.Sprintf("%s,%s", result, sslStatus)
	}

	results <- result
	//close(results)
}

func nsLookup(host string) (ipAddr, nsDur string) {
	if strings.Count(host, ":") >= 1 {
		nsDur = formatDuration(time.Since(time.Now()))
		return host, nsDur
	}
	hTmp := net.ParseIP(host)
	if hTmp == nil {
		nsStart := time.Now()
		nslook, err := net.LookupHost(host)
		if errorHandle(err, "nsLookup", false) {
			return host, "failed"
		}
		ipAddr = nslook[0]
		nsDur = formatDuration(time.Since(nsStart))
	} else {
		ipAddr = host
		nsDur = "0"
	}
	return ipAddr, nsDur
}

func scanIPLinux(target string, timeOut *time.Duration, icmpChan chan<- string) {
	tStart := time.Now()
	var cmd *exec.Cmd
	if strings.Count(target, ":") >= 2 {
		target = strings.TrimLeft(target, "[")
		target = strings.TrimRight(target, "]")
		cmd = exec.Command("ping6", "-c 1", "-i 1", target)
	} else {
		cmd = exec.Command("ping", "-c 1", "-i 1", target)
	}
	if verb {
		fmt.Printf("CMD: %v\n", cmd.Args)
	}
	// Use a bytes.Buffer to get the output
	var buf bytes.Buffer
	cmd.Stdout = &buf

	cmd.Start()

	// Use a channel to signal completion so we can use a select statement
	done := make(chan error)
	go func() { done <- cmd.Wait() }()

	// Start a timer
	timeout := time.After(*timeOut)

	// The select statement allows us to execute based on which channel
	// we get a message from first.
	select {
	case <-timeout:
		// Timeout happened first, kill the process and print a message.
		cmd.Process.Kill()
		icmpChan <- "ICMP Timeout"
	case err := <-done:
		// Command completed before timeout. Print output and error if it exists.
		//fmt.Println("Output:", buf.String())
		if err != nil {
			icmpChan <- "ICMP Fail"
		}
		tSince := formatDuration(time.Since(tStart))
		icmpChan <- tSince
	}
}

func scanIPWindows(target string, timeOut *time.Duration, icmpChan chan<- string) {
	//tmout := fmt.Sprintf("%v", timeOut.Nanoseconds()/1000000)
	tStart := time.Now()
	cmd := exec.Command("ping", "-n", "1", target)
	//fmt.Printf("Command: %v\n", cmd.Args)
	// Use a bytes.Buffer to get the output
	var buf bytes.Buffer
	cmd.Stdout = &buf

	cmd.Start()

	// Use a channel to signal completion so we can use a select statement
	done := make(chan error)
	go func() { done <- cmd.Wait() }()

	// Start a timer
	timeout := time.After(*timeOut)

	// The select statement allows us to execute based on which channel
	// we get a message from first.
	select {
	case <-timeout:
		// Timeout happened first, kill the process and print a message.
		cmd.Process.Kill()
		icmpChan <- "ICMP Timeout"
	case err := <-done:
		// Command completed before timeout. Print output and error if it exists.
		//fmt.Println("Output:", buf.String())
		if err != nil {
			icmpChan <- "ICMP Fail"
		}
		tSince := formatDuration(time.Since(tStart))
		icmpChan <- tSince
	}
}

func removeDuplicates(scanAddr []string) []string {
	encountered := map[string]bool{}
	result := []string{}

	for v := range scanAddr {
		if encountered[scanAddr[v]] == true {
			// Do not add duplicate.
		} else {
			// Record this element as an encountered element.
			encountered[scanAddr[v]] = true
			// Append to result slice.
			result = append(result, scanAddr[v])
		}
	}
	// Return the new slice.
	return result
}

func usage() {
	fmt.Println(`
Tcpscan:
--------
tcpscan is a tool for checking basic network connectivity. Unlike other tools
like nmap or nc, tcpscan is not a discovery tool, but a validation  tool.
When all you need is to find out if a port is open on system, or if there 
is a firewall in the way.

Extended Usage Information:
---------------------------
-f, --file:
	In this instance you pass the path to a file containing ip addresses 
	and ports to be scanned.  File format is <ipaddress>:<port> One 
	address per line:
		10.1.1.1:22
		10.1.1.2:22
		-- and so on --

-O, --output:
	Tcpscan has a few different formats:
		grid  -- Graphical grid
		gridt -- Text grid (mysql like, default)
		text  -- Text only no headers. Useful when used in script.
		tab	  -- No gridlines.

-o, --open:
	Only show ports that are open. This is useful when scanning an 
	entire subnet.

-t, --timeout:
	Set the timeout.  Timeout can be set by typing a value.
		100ns -- 100 Nano seconds
		100us -- 100 Microseconds
		100ms -- 100 Milliseconds
		1s    -- 1 second

-e, --excel
	Output to excel file
		-e MyExcelFile.xlsx
-c, --calc
	Subnet Calculator
		tcpscan -c 10.1.1.0/24
		tcpscan --calc=10.1.1.0/24

Status:
-------
What the 'Status' means:
	Open 	 --	TCP Packet reached the system, system is listening on the 
			port.
	Closed 	 --	TCP Packet reached the system, system is not listening on
			the port.
	Filtered --	TCP Packet never reaches the system. System could be down, 
			or the port blocked at a switch / router. Try pinging the host
			if you see this, and if ping is successful, good chance a router
			is blocking it.

NOTE: If you see ICMP 'Failed' and this message:
  "Error listening for ICMP packets: listen ip4:icmp : socket: operation not permitted"
  Also, ICMP doesn't work on Windows. Its normal to see a 0 for ICMP.

Move tcpscan to /usr/local/bin and run this command:
  sudo chown root:root /usr/local/bin/tcpscan
  sudo chmod 4755 /usr/local/bin/tcpscan

About:
------
Version v1.8.10 -- June 29, 2020

`)
}
