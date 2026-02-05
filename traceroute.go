package main

import (
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/net/ipv4"
)

func main() {
	ipAddr, err := net.ResolveIPAddr("ip", os.Args[1])
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Printf("Traceroute to %s:\n", ipAddr.String())

	const maxHops = 64
	ttl := 1
	for ; ttl < maxHops; ttl++ {
		conn, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
		if err != nil {
			fmt.Println(err)
			continue
		}

		conn.SetDeadline(time.Now().Add(time.Second))
		defer conn.Close()

		// Set the TTL option
		p := ipv4.NewPacketConn(conn)
		p.SetTTL(ttl)
		controlMessage := &ipv4.ControlMessage{
			TTL: ttl,
		}
		// Send a ICMP echo request
		_, err = p.WriteTo([]byte{8, 0, 0, 0, 0, 0, 0, 0}, controlMessage, ipAddr)
		if err != nil {
			fmt.Println(err)
			continue
		}

		// Receive the ICMP reply
		buf := make([]byte, 1024)
		_, _, err = conn.ReadFrom(buf)
		if err != nil {
			fmt.Println(err)
			continue
		}

		src := conn.LocalAddr()
		fmt.Printf("%v\t%v\n", ttl, src)

		// If we've reached the destination, then exit the loop
		if src.String() == ipAddr.String() {
			break
		}
	}
}
