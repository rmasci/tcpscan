/*
Copyright © 2020 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/rmasci/tools"

	"github.com/spf13/cobra"
	"gopkg.in/natefinch/lumberjack.v2"
)

type TcpScan struct {
	Hosts    []string `json:"Hosts"`
	Output   string   `json:"Output"`
	Ping     bool     `json:"Ping"`
	DNS      bool     `json:"DNSResolve"`
	Protocol string   `json:"Protocol"`
	SSL      bool     `json:"SSL"`
	Timeout  string   `json:"Timeout"`
}

/*
type DataHost struct {
	HostPort string `json:"HostPort"`
}
*/
var (
	srvPort string
	sslKEY  string
	sslCRT  string
	lgOut   *log.Logger
	logFile string
)

// serverCmd represents the server command
var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Tcpscan is made for scanning for open / closed / filtered ports.",
	Long: `The goal of tcpscan is to provide a way to be able to scan ports, to
	check if those ports are open / closed / filtered but without creating a 
	scanning tool that can really look for vulnerabilities. 
	
	Server allows you to run this on a middle server. So that you can send 
	a PUT or POST to a tcpscan server, the scan will be performed from that server
	and sent back to the requestor.
	
	Server also allows southbound checks...z`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("server called")
		ListenAndServe()
	},
}

func init() {

	rootCmd.AddCommand(serverCmd)
	// Here you will define your flags and configuration settings.
	serverCmd.Flags().StringVarP(&srvPort, "port", "p", "8888", "Port to run on.")
	serverCmd.Flags().StringVarP(&sslKEY, "ssl-key", "K", "", "SSL Key pem file location")
	serverCmd.Flags().StringVarP(&sslCRT, "ssl-crt", "c", "", "SSL CRT pem file location")
	serverCmd.Flags().StringVarP(&logFile, "log-file", "l", "tcpscan.srv.log", "Log File for server.")
	serverCmd.Flags().BoolVarP(&v.Verb, "verbose", "v", false, "Verbose Mode")
}

func ListenAndServe() {
	//start logging
	var err error
	daemon := false
	if logFile == "" {
		logFile = os.Args[0]
	}
	lf, err := os.OpenFile(logFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0664)
	if err != nil {
		fmt.Printf("Can't open log %v\n", logFile)
		os.Exit(1)
	}
	lgOut = log.New(lf, "", log.LstdFlags)
	lgOut.SetOutput(&lumberjack.Logger{
		Filename:   logFile,
		Compress:   true,
		MaxSize:    50,
		MaxBackups: 5,
	})

	lgOut.Printf("PID: %v\n", os.Getpid)
	// Start Server
	//http.HandleFunc("/", mainPage)
	//http.HandleFunc("/scanform/", processForm)
	http.Handle("/scan/", (http.StripPrefix("/scan/", http.HandlerFunc(processJson))))
	http.Handle("/", (http.StripPrefix("/", http.HandlerFunc(mainPage))))
	http.Handle("/scanform/", (http.StripPrefix("/scanform/", http.HandlerFunc(processForm))))
	//http.HandleFunc("/scanform/", processForm)
	s := &http.Server{
		// Listen on ALL addresses on port
		Addr:           ":" + srvPort,
		Handler:        nil,
		ReadTimeout:    300 * time.Second,
		WriteTimeout:   300 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	asSrv = true
	if daemon {
		fmt.Printf("Normally I'd daemonize... for now... just wait.\n")
		lgOut.Printf("Normally I'd daemonize... for now... just wait.\n")
	}
	lgOut.Printf("Server: %v\n", s.Addr)
	// Start webserver
	fmt.Println(s.ListenAndServe())
	lgOut.Println(s.ListenAndServe())

}

// Beef this up. Put back a chedk for method... Find out why restcall screwed up.

func processJson(w http.ResponseWriter, req *http.Request) {
	meth := strings.ToLower(req.Method)
	meth = strings.ToLower(meth)
	fmt.Println("Process JSON Method:", meth)

	var pload TcpScan
	/*jsonByte, err := ioutil.ReadAll(req.Body)
	if err != nil {
		lgOut.Printf("ERROR: %v\n", err)
		http.Error(w, http.StatusText(500), 500)
		fmt.Fprintf(w, "Could not read JSON %v", err)
		return
	}
	*/
	err := json.NewDecoder(req.Body).Decode(&pload)
	if err != nil {
		lgOut.Printf("ERROR %v\n", err)
		http.Error(w, http.StatusText(500), 500)
		fmt.Fprintf(w, "Error in JSON Decode.\n")
		return
	}
	// Now that it's a struct... We can parse that struct.
	if pload.Output == "" {
		outF = "json"
	} else {
		outF = pload.Output
	}
	if pload.Ping {
		icmpCk = true
	} else {
		icmpCk = false
	}
	if pload.SSL {
		sslCheck = true
	} else {
		sslCheck = false
	}
	if pload.DNS {
		dnsCk = true
	} else {
		dnsCk = false
	}
	if pload.Protocol == "" {
		proto = "tcp"
	} else {
		proto = pload.Protocol
	}
	if pload.Timeout == "" {
		timeout = "1s"
	} else {
		timeout = pload.Timeout
	}
	scanout := StartScan(pload.Hosts)
	v.Println("Done Scan")
	lgOut.Println("Done Scan")
	if scanout != "" {
		fmt.Fprintln(w, scanout)
	} else {
		fmt.Fprintln(w, "No Return")
	}
}

func processForm(w http.ResponseWriter, req *http.Request) {
	var sHosts []string
	var buildJson bool
	lgOut.Println("Processing Form")
	v.Println("Processing Form")
	for inDex, val := range req.URL.Query() {
		lgOut.Printf("val: %v inDex: %v\n", val[0], inDex)
		switch inDex {
		case "ping":
			icmpCk = true
		case "sslcheck":
			sslCheck = true
		case "dnsresolv":
			dnsCk = true
		case "Build Payload":
			lgOut.Printf("Build Json")
			buildJson = true
		case "hostlist":
			v, err := url.QueryUnescape(val[0])
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, "ERROR in Form")
				return
			}
			sHosts = strings.Fields(v)
		case "output":
			outF = val[0]
		}
	}
	if buildJson == false { //StartScan(sHosts, w)
		scanout := StartScan(sHosts)

		v.Println("Done Scan")
		lgOut.Println("Done Scan")
		if scanout != "" {
			fmt.Fprintln(w, scanout)
		} else {
			fmt.Fprintln(w, "No Return")
		}
	} else {
		var tscan TcpScan
		scheme := "http"
		pUrl := fmt.Sprintf("%s://%s", scheme, req.Host)
		tscan.Hosts = sHosts
		tscan.Output = outF
		tscan.Ping = icmpCk
		tscan.DNS = dnsCk
		tscan.Protocol = "tcp"
		tscan.SSL = sslCheck
		tscan.Timeout = "1s"
		outByte, err := json.Marshal(tscan)
		tools.ErrorHandle500(err, "Marshal JSON", w)
		fmt.Fprintf(w, "<html><h2>Payload:</h2>%s<br>", outByte)
		fmt.Fprintf(w, "<br><br>Example:<br>restcall post -p payload.json %s/scan<br>", pUrl)
	}
}

func isJSONString(s string) bool {
	var js map[string]interface{}
	return json.Unmarshal([]byte(s), &js) == nil
}
func mainPage(w http.ResponseWriter, req *http.Request) {
	// Since the URL is coming from Go, I doubt there will be an error, so I used a _.
	var scheme string
	if req.TLS == nil {
		scheme = "http"
	} else {
		scheme = "https"
	}
	outHtml := ScanForm(scheme, req.Host)
	fmt.Fprintln(w, outHtml)
	lgOut.Printf("Host: %v://%v\n", scheme, req.Host)
	v.Printf("Host: %v://%v\n", scheme, req.Host)
	lgOut.Printf("Form Sent.")
	v.Println("Form Sent.")
}

// GetFQDN gets fully qualified domain name of server
func GetFqdn() (string, error) {
	cmd := exec.Command("/bin/hostname", "-f")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("Error when get_hostname_fqdn: %v", err)
	}
	fqdn := out.String()
	fqdn = fqdn[:len(fqdn)-1] // removing EOL

	return fqdn, nil
}

/* Documentation This is the json and other bits...

//inbound json rest call. IF application in call is set to json.... If not then just take plaintext as a list -- same format as the -f for scan or pipped input to scan.
// Method here is PUT - first line *only* specifys how you want it to output. If not there then go with the default.
/*plaintext list:
  output:html
  one.mydomain.com:22
  two.mydomain.com:8443
  two.mydomain.com:22
  ...
  https://fifty.mydomain.com
  http://fiftyone.mydomain.com
Output is Grid <pre>. Just get the list and send it to scan same way you'd scan from piped or file input.

If you want to do more with each scan then send it as a JSON rest POST. Default output is JSON. You can specify json, html, pre (grid).
ScanResult JSON Output
{
  "Results":
  [
    {
      "Hostname": "One",
      "Port": "22",
      "Result": "String",
      "Dur": "String",
      "ICMPDur": "JSON",
      "SSLCk": "String"
    }
  ]
}

TcpScan Json
{
  "Hosts": [
    {
      "Hostname": "one.host.mydomain.com",
      "Port": "22"
    }
  ],
  "SSL": true,
  "Ping": true,
  "Protocol": "tcp",
  "Output": "JSON",
  "Timeout": "1s"
}
*/
