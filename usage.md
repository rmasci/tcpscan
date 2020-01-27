# TCPSCAN Usage

This is the tcpscan --help message:

```

] $ tcpscan --help  

  -C, --calc              Subnet Calculator.  ex: tcpscan -c 10.1.1.0/24
  -c, --comment string    Add a comment. Replaces 'Address' in output header of table.
  -d, --dns               Enable DNS Check
  -e, --excel string      Save output in Excel Format.
  -f, --file string       A filename containing a list of IP addresses to scan, separated by newlines.
  -h, --help              help
  -i, --icmp              Enable ICMP Check
  -x, --no-format         Do not format time output. Output will be in microseconds.
  -o, --open              Only show open ports.
  -O, --output string     output: grid, gridt, text, csv, tab (default "gridt")
  -p, --port string       Port to scan (default "noport")
  -P, --protocol string   Protocol to use, tcp is default. (default "tcp")
      --sc string         Add a comment to the status field. Must be 3 fields comma separated. Default is "Open,Closed,Filtered".
  -s, --ssl               Check SSL Cert.
  -S, --stats             Print Stats. Usefull when scanning more than one host.
  -t, --timeout string    Timeout value. 5s= 5 seconds, 5ms=5 milliseconds and so on (5ns, 5us). (default "500ms")
  -v, --verbose           Verbose
      --vv                Very Verbose

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
This will put a suid on tcpscan, and it runs as root, but ping is also suid to root.

About:
------
Version v1.8.5 -- January 27, 2020
```

