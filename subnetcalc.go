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
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/SDNSquare/ipsubnet"
)

func subnetCalc(ipStr string) {
	_, _, err := net.ParseCIDR(ipStr)
	errorHandle(err, "Parse CIDR", true)
	ipSub := strings.Split(ipStr, "/")
	if len(ipSub) <= 1 {
		os.Exit(1)
	}
	var output []string
	ipSubInt, err := strconv.Atoi(ipSub[1])
	errorHandle(err, "SubnetCalc", true)
	sub := ipsubnet.SubnetCalculator(ipSub[0], ipSubInt)
	//fmt.Printf("Host: %v CIDR: /%v\n\n",ipSub[0], ipSub[1])
	output = append(output, fmt.Sprintf("Host Address\t\t- %v", sub.GetIPAddress()))
	output = append(output, fmt.Sprintf("Subnet Mask\t\t- %v", sub.GetSubnetMask()))
	output = append(output, fmt.Sprintf("Network Address\t\t- %v", sub.GetNetworkPortion()))
	output = append(output, fmt.Sprintf("Broadcast Address\t- %v", sub.GetBroadcastAddress()))
	output = append(output, fmt.Sprintf("Network Range\t\t- %v - %v", sub.GetNetworkPortion(), sub.GetBroadcastAddress()))
	uStartArr := sub.GetNetworkPortionQuards()
	uFirst3 := fmt.Sprintf("%v.%v.%v", uStartArr[0], uStartArr[1], uStartArr[2])
	usableStart := fmt.Sprintf("%v.%v", uFirst3, uStartArr[3]+1)
	//ipEnd := fmt.Sprintf("%v.%v", uFirst3, ipStartArr[3]+sub.GetNumberAddressableHosts())
	uEndArr := strings.Split(sub.GetBroadcastAddress(), ".")
	uLastInt, _ := strconv.Atoi(uEndArr[3])
	usableEnd := fmt.Sprintf("%v.%v.%v.%v", uEndArr[0], uEndArr[1], uEndArr[2], uLastInt-1)
	output = append(output, fmt.Sprintf("Usable Range\t\t- %v - %v", usableStart, usableEnd))
	output = append(output, fmt.Sprintf("Addresses in Network\t- %v", sub.GetNumberIPAddresses()))
	output = append(output, fmt.Sprintf("Usable Addresses\t- %v", sub.GetNumberAddressableHosts()))
	fmt.Println("")
	for _, l := range output {
		fmt.Printf("\t%v\n", l)
	}
	fmt.Println("")
}
