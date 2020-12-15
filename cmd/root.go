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
	"os"

	"github.com/spf13/cobra"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"
)

var cfgFile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "tcpscan",
	Short: "Tcpscan is made for scanning for open / closed / filtered ports.",
	Long: `The goal of tcpscan is to provide a way to be able to scan ports, to
  check if those ports are open / closed / filtered but without creating a 
  scanning tool that can really look for vulnerabilities. 
  
  Netcat for example was written to exploit vulnerabilitys, nmap is also
  used to learn and exploit vulnerabilities, tcpscan just scans, pings, does
  TLS checking.  It can scan a range of ports, but only 2000 of them at a time. 
  It's not meant to be a discovery tool, but validation tool.
    scan <host>
    server
    calc <subnet/cidr>
  `,
	Run: func(cmd *cobra.Command, args []string) {},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	var cmdPassed bool
	cobra.OnInitialize(initConfig)
	validCmd := [3]string{"scan", "server", "calc"}
	//what this does is set what 'default' command is. If nothing passed then it's a scan.

	for _, a := range os.Args[1:] {
		for _, hsCmd := range validCmd {
			if a == hsCmd {
				cmdPassed = true
				break
			}
		}
		if cmdPassed == true {
			break
		}
	}
	if cmdPassed == false {
		// this means user didn't specify 'scan' or 'server' so we do it for them. :)
		os.Args = append([]string{os.Args[0], "scan"}, os.Args[1:]...)
	}

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.tcpscan.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Search config in home directory with name ".tcpscan" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName(".tcpscan")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}
