# TCPSCAN
Table of Contents
=================

   * [TCPSCAN](#tcpscan)
      * [Installing](#installing)
      * [Usage](#usage)
      * [ex output:](#ex-output)
         * [What if I don't know the port?](#what-if-i-dont-know-the-port)
         * [Scan a range of ports](#scan-a-range-of-ports)
         * [Scan a subnet](#scan-a-subnet)
         * [Scan from a file](#scan-from-a-file)
         * [Include Ping](#include-ping)
         * [DNS Lookup of host](#dns-lookup-of-host)
         * [Only Show Open](#only-show-open)
         * [Scan from piped input](#scan-from-piped-input)
      * [Format Output](#format-output)
         * [Text Grid (Default)](#text-grid-default)
         * [CSV Output](#csv-output)
         * [Excel output](#excel-output)
         * [Graphical Grid](#graphical-grid)
         * [Tab based Grid](#tab-based-grid)
         * [Text only option](#text-only-option)

Most other tools like nc or nmap are tools that are a swiss army knife of things you can do -- some of which can be used for purposes that can harm a system or be used to hack a system.  

NetCat is a wonderful tool, and it does a lot more than tcpscan is designed to do; however some of those 'features' can be used to exploit your system, after all NetCat was was originally written to be a hacking tool.  Having NMap or NetCat on your system is like leaving a set of lockpicks outside the door of your home. Not saying tcpscan can't be used for hacking, just isn't as good -- it's main purpose is to validate or verify a known host has a port that's open. 

For the most part tcpscan is written to be a tool that is used to verify what you already know should exist, not as a discovery tool to reveal what exploits exist.  Tcpscan is written in Go, and originally was written as an example in using go routines  so it takes advantage of Go's threading. As a result tcpscan runs a faster than nc or nmap, buy you'd have to be scanning an entire subnet to see that.  The syntax is also designed to be easy to use. 


Tcpscan:
* Scan Hosts / Subnets
* Pass file for input / file list can be piped in: 
```
cat /etc/hosts | awk '{print $1}' | tcpscan -p 22
```
* Domain Name lookup (-d option)
* ICMP Optional to test ping as well as ports (Uses system 'ping' command) (-i for icmp)
* SSL check -- Will tell you if you can connect on an https port and if the server certificate is valid. (-s)

Tcpscan does a few things but mainly it's there to verify. So if your system depends on another system to perform it's function like a call to a database server or rest call to another system for information, tcpscan is meant to be a tool to verify that. 

Example of Port Scan, SSL check, ICMP PING, and Domain lookup:
```
tcpscan] ] $ tcpscan https://www.google.com -i -d -s
+-------------------+---------+-----------+------------+------------+-------------+---------------------------+
|           Address |    Port |    Status |        TCP |       ICMP |    NSLookup |                       SSL |
+===================+=========+===========+============+============+=============+===========================+
|    216.58.193.132 |     443 |      Open |    39.05ms |    66.06ms |     42.43ms |    TLS v1.2 / OK: 63 days |
+-------------------+---------+-----------+------------+------------+-------------+---------------------------+
```
So if you were troubleshooting a connection issue, or perhaps failing over to your disaster recovery site, with one command you can tell: 1. Port is open, 2. Ping works, 3. NSLookup OK (System is in DNS), 4. SSL checks good.

Status Meaning:
* Open -- TCP Packet reached the system, system is listening on the port.
* Closed -- TCP Packet reached the system, system is not listening on the port.
* Filtered -- TCP Packet never reaches the system. 
**System could be down
**port blocked at a switch / router. 

Try pinging the host if you see this, -- or use the -i switch -- and if ping is successful, good chance a router is blocking it.

 can have an output in:
* grid format default
* tab 
* text -- for use in scripts
* Excel. Great for generating a report  

You can scan more than one host by passing a file as a parameter, or by scanning an entire subnet '10.1.1.0/24'.  NOTE: Tcpscan will ONLY scan 2048 hosts and ports at a time, so it's impossible to do a scan that could be harmful to the network or host.

Binaries can be found under the sdn-tools/tcpscan directory. Yes there is a windows version and Yes it doesn't require Administrator rights to install. Just copy it, and run!
```
C:\tcpscan\binaries\win64>tcpscan www.google.com -p 443 -d -s -i -t 30ms
+--------------------+---------+-----------+------------+------------+-------------+-----------------+
|            Address |    Port |    Status |        TCP |       ICMP |    NSLookup |             SSL |
+====================+=========+===========+============+============+=============+=================+
|    www.google.com  |     443 |      Open |   179.53ms |   184.72ms |    191.92ms |    OK: 235 days |
+--------------------+---------+-----------+------------+------------+-------------+-----------------+
```

## Installing
Tcpscan comes as a single binary, and all you have to do is copy it. Go to the binaries directory and just copy the binary to your system. Be sure to set it as executable on Linux / Mac systems.

You can also just install the binary for your system instead of downloading the whole repository. See the binaries directory in this repository.

## Usage
See [extended](https://github.com/rmasci/tcpscan/blob/master/usage.md) usage.

Usage is pretty simple, by default port 22 is used if no port specified.  Ports can be guessed using a string like this:  ntp://10.1.1.1. More on that below.

NOTE: Tcpscan was compiled with a default timeout of 500ms. Please use the -t option to up the timeout when scanning hosts that might be open to the port, but are latent
tcpscan <hostname> -p <port>

```
] $ tcpscan someserver.mydomain.com -p 22,443
+--------------------------+---------+-----------+------------+
|                  Address |    Port |    Status |        TCP |
+==========================+=========+===========+============+
|  somesevrer.mydomain.com |      22 |    Closed |    79.96ms |
|  someserver.mydomain.com |     443 |      Open |    79.08ms |
+--------------------------+---------+-----------+------------+
```
### What if I don't know the port?
Tcp scan can try to guess the port you're looking for, just put the name of the service (/etc/services) in front of the host:
```
] $ tcpscan ipp://10.1.1.1
+-------------+---------+-----------+-----------+
|     Address |    Port |    Status |       TCP |
+=============+=========+===========+===========+
|    10.1.1.1 |     631 |      Open |    5.25ms |
+-------------+---------+-----------+-----------+
```
In this case it looked for the internet printing protocol on port 631.

### Scan a range of ports
```
] $ tcpscan someserver.mydomain.com -p 443-450
+--------------------------+---------+-----------+-------------+
|                  Address |    Port |    Status |         TCP |
+==========================+=========+===========+=============+
|  someserver.mydomain.com |     443 |      Open |    155.96ms |
|  someserver.mydomain.com |     444 |    Closed |    159.14ms |
|  someserver.mydomain.com |     445 |    Closed |    171.87ms |
|  someserver.mydomain.com |     446 |    Closed |    170.36ms |
|  someserver.mydomain.com |     447 |    Closed |    171.31ms |
|  someserver.mydomain.com |     448 |    Closed |    170.81ms |
|  someserver.mydomain.com |     449 |    Closed |    171.52ms |
|  someserver.mydomain.com |     450 |    Closed |    170.75ms |
+--------------------------+---------+-----------+-------------+
```
####NOTE: Tcpscan will only can 2048 hosts / ports at the same time. 
```
tcpscan 10.1.1.12 10.1.1.12 -p 22,23 
```
would count as 4. 
### Scan a subnet
```
] $ tcpscan 192.168.2.148/29 -p 22,8443
+-------------------+---------+-------------+-------------+
|           Address |    Port |      Status |         TCP |
+===================+=========+=============+=============+
|     192.168.2.145 |      22 |    Filtered |    500.21ms |
|     192.168.2.145 |    8443 |    Filtered |    500.17ms |
|     192.168.2.146 |      22 |    Filtered |    500.22ms |
|     192.168.2.146 |    8443 |    Filtered |    500.22ms |
|     192.168.2.147 |      22 |        Open |    184.15ms |
|     192.168.2.147 |    8443 |      Closed |    178.65ms |
|     192.168.2.148 |      22 |        Open |    206.54ms |
|     192.168.2.148 |    8443 |        Open |    204.48ms |
|     192.168.2.149 |      22 |    Filtered |    501.09ms |
|     192.168.2.149 |    8443 |    Filtered |    501.03ms |
|     192.168.2.150 |      22 |    Filtered |    500.27ms |
|     192.168.2.150 |    8443 |    Filtered |    501.22ms |
+------```-------------+---------+-------------+-------------+
```
### Scan from a file
File contains one <IP>:<Port> per line:

File test.txt:
```
192.168.2.145
192.168.2.146
192.168.2.147
192.168.2.148
192.168.2.149
192.168.2.150
```
```
] $ tcpscan -f test.txt
+-------------------+---------+-------------+-------------+
|           Address |    Port |      Status |         TCP |
+===================+=========+=============+=============+
|     192.168.2.145 |      22 |    Filtered |    503.80ms |
|     192.168.2.146 |      22 |    Filtered |    503.70ms |
|     192.168.2.147 |      22 |        Open |    168.04ms |
|     192.168.2.148 |      22 |        Open |    203.54ms |
|     192.168.2.149 |      22 |    Filtered |    503.65ms |
|     192.168.2.150 |      22 |    Filtered |    503.88ms |
+-------------------+---------+-------------+-------------+
```

### Include Ping
Use -i (ICMP) to use system ping

```
] $ tcpscan -f test.txt -i
+-------------------+---------+-------------+-------------+--------------+
|           Address |    Port |      Status |         TCP |         ICMP |
+===================+=========+=============+=============+==============+
|     192.168.2.145 |      22 |    Filtered |    503.80ms |      97.45ms |
|     192.168.2.146 |      22 |    Filtered |    503.70ms |      95.34ms |
|     192.168.2.147 |      22 |        Open |    168.04ms |     105.05ms |
|     192.168.2.148 |      22 |        Open |    203.54ms |    ICMP Fail |
|     192.168.2.149 |      22 |    Filtered |    503.65ms |     104.24ms |
|     192.168.2.150 |      22 |    Filtered |    503.88ms |    ICMP Fail |
+-------------------+---------+-------------+-------------+--------------+
```

### DNS Lookup of host
Use a -d to do NSLookups of hosts. (Doesn't do reverse lookups)
srverlist.txt:
```
https://www.google.com
https://www.yahoo.com
https://www.facebook.com
https://www.amazon.com
https://www.att.com
```
[rx7322@mba-rx7322 ~/
```
] $ tcpscan -f srverlist.txt -d 
+-------------------+---------+-----------+------------+-------------+
|           Address |    Port |    Status |        TCP |    NSLookup |
+===================+=========+===========+============+=============+
|     172.217.2.228 |     443 |      Open |    56.98ms |      3.29ms |
|        72.30.35.9 |     443 |      Open |    83.78ms |     55.50ms |
|     157.240.28.35 |     443 |      Open |    60.27ms |     60.42ms |
|    13.226.103.229 |     443 |      Open |    61.39ms |     51.59ms |
|     23.75.231.235 |     443 |      Open |    46.69ms |     46.44ms |
+-------------------+---------+-----------+------------+-------------+

Scanned 5 hosts/ports in 144.85ms
```

### Only Show Open
Using a -o will limit the output to only open.
```
] $ tcpscan -f test.txt -o
+-------------------+---------+-----------+-------------+
|           Address |    Port |    Status |         TCP |
+===================+=========+===========+=============+
|     192.168.2.147 |      22 |      Open |    217.10ms |
|     192.168.2.148 |      22 |      Open |    216.87ms |
+-------------------+---------+-----------+-------------+
```
### Scan from piped input
```
] $ grep someserevers /etc/hosts | grep | awk '{print $1}' | tcpscan -p 22
+------------------+---------+-----------+------------+
|          Address |    Port |    Status |        TCP |
+==================+=========+===========+============+
|    10.200.126.66 |      22 |      Open |    61.89ms |
|    10.200.126.67 |      22 |      Open |    52.85ms |
|    10.200.126.68 |      22 |      Open |    56.52ms |
|    10.200.126.71 |      22 |      Open |    46.08ms |
|    10.200.126.72 |      22 |      Open |    48.65ms |
|    10.200.126.69 |      22 |      Open |    61.33ms |
|    10.200.126.70 |      22 |      Open |    58.15ms |
|    10.200.126.73 |      22 |      Open |    57.56ms |
|    10.200.127.68 |      22 |      Open |    58.83ms |
|    10.200.127.69 |      22 |      Open |    50.79ms |
|    10.200.127.70 |      22 |      Open |    58.84ms |
|    10.200.127.73 |      22 |      Open |    58.04ms |
|    10.200.127.74 |      22 |      Open |    57.42ms |
|    10.200.127.71 |      22 |      Open |    57.00ms |
|    10.200.127.72 |      22 |      Open |    56.22ms |
|    10.200.127.75 |      22 |      Open |    54.74ms |
+------------------+---------+-----------+------------+

Scanned 16 hosts/ports in 62.73ms
```
## Format Output
You have a few options of how the output is rendered by passing a -F.

### Text Grid (Default) 
The default output is gridt (grid text -- looks like mysql query)
```
] $ tcpscan -f test.txt -O gridt
+-------------------+---------+-------------+-------------+
|           Address |    Port |      Status |         TCP |
+===================+=========+=============+=============+
|     192.168.2.145 |      22 |    Filtered |    503.80ms |
|     192.168.2.146 |      22 |    Filtered |    503.70ms |
|     192.168.2.147 |      22 |        Open |    168.04ms |
|     192.168.2.148 |      22 |        Open |    203.54ms |
|     192.168.2.149 |      22 |    Filtered |    503.65ms |
|     192.168.2.150 |      22 |    Filtered |    503.88ms |
+-------------------+---------+-------------+-------------+
```
### CSV Output 
Useful if you want to import into Excel. (Or just use the Excel option below.)
```
] $ tcpscan -f test.txt -F csv
Address,Port,Status,Time
192.168.2.148,22,Open,188.66ms
192.168.2.147,22,Open,188.93ms
192.168.2.149,22,Filtered,504.30ms
192.168.2.146,22,Filtered,504.30ms
192.168.2.150,22,Filtered,504.66ms
192.168.2.145,22,Filtered,504.68ms
```
### Excel output
Why have an excel option? Because the person that wrote this package for Go did such an awesome job it was simple to add in. So if it's simple, why not right?
"github.com/360EntSecGroup-Skylar/excelize"
Plus if you want a report to send on to others -- well this gets you started. 
```
From: OperationsTeam
To: OperationsManager
CC: OperationsSVP
Subj: Connectivity in Prod

Attached you'll find a report showing the TCP connectivity that our production systems require. You'll see the systems and the ports as well as showing if those ports are open from our Production systems.
```
```
] $ tcpscan -e ExcelReport.xlsx -f LongListOfHosts.txt
Wrote 45 rows to ExcelReport.xlsx
] $
```
### Graphical Grid
Cooler looking spreadsheet like output.  Why did I include this? Because GoTabulate is such and awesome package. I added some changes to it to suite my purposes -- which means gotabulate was well written and easy to understand for others to quickly adapt. Awesome Job
https://github.com/bndr/gotabulate
```
] $ tcpscan -f test.txt -O grid
╒═══════════════════╤═════════╤═════════════╤═════════════╕
│           Address │    Port │      Status │         TCP │
╞═══════════════════╪═════════╪═════════════╪═════════════╡
│     192.168.2.145 │      22 │    Filtered │    501.00ms │
│     192.168.2.146 │      22 │    Filtered │    500.92ms │
│     192.168.2.147 │      22 │        Open │    196.44ms │
│     192.168.2.148 │      22 │        Open │    196.22ms │
│     192.168.2.149 │      22 │    Filtered │    501.53ms │
│     192.168.2.150 │      22 │    Filtered │    501.69ms │
└───────────────────┴─────────┴─────────────┴─────────────┘
```
### Tab based Grid
Useful when you want to pipe the results to another program such as Grep or Awk. Better yet use the -O text option for scripting.
(Again this is just simple with Gotabulate)
```
] $ tcpscan -f test.txt -F tab

           Address 	    Port 	      Status 	         TCP

    192.168.2.145 	      22 	    Filtered 	    500.85ms
    192.168.2.146 	      22 	    Filtered 	    500.91ms
    192.168.2.147 	      22 	        Open 	    177.32ms
    192.168.2.148 	      22 	        Open 	    179.77ms
    192.168.2.149 	      22 	    Filtered 	    500.74ms
    192.168.2.150 	      22 	    Filtered 	    500.88ms
```
### Text only option
Leaves out the header "Address, Port, Status, TCP"
```
] $ tcpscan -f iplist.txt -O text -p 80
172.217.2.228 80 Open 40.30ms
23.75.231.235 80 Open 40.47ms
157.240.28.35 80 Open 67.01ms
13.226.103.229 80 Open 67.21ms
72.30.35.9 80 Open 80.61ms
```
Formats it as just plain text to which you can grep, awk, sed etc. over.

# Credits
Tcpscan would not be possible without thanks to the Go Authors and to the following packages:

	"github.com/360EntSecGroup-Skylar/excelize"
	"github.com/rmasci/gotabulate"
	"github.com/tevino/tcp-shaker"
	"github.com/brotherpowers/ipsubnet"
   "github.com/spf13/pflag"