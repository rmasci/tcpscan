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
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/brotherpowers/ipsubnet"
	"github.com/spf13/cobra"
)

// calcCmd represents the calc command
var calcCmd = &cobra.Command{
	Use:   "calc",
	Short: "tcpscan subnet calculator",
	Long:  "tcpscan calc 10.1.1.1/25",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("calc called")
		argStr := strings.Join(args, " ")
		subnetCalc(argStr)
	},
}

func init() {
	rootCmd.AddCommand(calcCmd)

	// Here you will define your flags and configuration settings.
	//Persistent Flags which will work for this command
	// calcCmd.PersistentFlags().String("foo", "", "A help for foo")

	// local flags which will only run when this command is called directly, e.g.:
	// calcCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

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
