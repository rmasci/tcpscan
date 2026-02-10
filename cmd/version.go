package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Version is the version of the rip tool.
// This is injected at build time using ldflags.
// Example build command:
//
//	go build -ldflags "-X github.com/rmasci/rip/cmd.Version=v0.2.0" .
//
// Format: v0.1.0
var Version = "v0.1.0"

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version of rip",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("rip version %s\n", Version)
	},
}

// init registers the version command
func init() {
	rootCmd.AddCommand(versionCmd)
}
