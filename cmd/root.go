package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "rip",
	Short: "A CLI tool for ripping and organizing media files",
	Long: `Rip is a command-line tool designed to simplify the process of ripping and organizing media files.
It supports DVDs and TV shows, automating tasks like metadata fetching, file organization, and cleanup.
This tool is ideal for creating a well-structured media library compatible with platforms like Plex.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once per run.
func Execute() {
	// Check for -v or --version flag before processing commands
	for _, arg := range os.Args[1:] {
		if arg == "-v" || arg == "--version" {
			fmt.Printf("rip version %s\n", Version)
			os.Exit(0)
		}
	}

	// Load configuration
	AppConfig = LoadConfig()

	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

// AppConfig holds the global application configuration
var AppConfig *Config

// init initializes the root command and configures global flags.
// Currently, no persistent flags are configured, but this function
// serves as a place for future global configuration.
func init() {
	// Define global flags and configuration settings
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// Example: rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.rip.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

// ejectDisc ejects the disc from the specified device using the eject command.
// It wraps the system eject command to safely remove the disc from the drive.
//
// Parameters:
//
//	devicePath - the device path (e.g., "/dev/sr0")
//
// Returns an error if the eject command fails or the device is not accessible.
func ejectDisc(devicePath string) error {
	ejectCmd := exec.Command("eject", devicePath)
	return ejectCmd.Run()
}

// extractDevicePath converts a disc specification to a device path.
// It extracts the numeric drive index from a disc specification (e.g., "disc:0")
// and converts it to a device path (e.g., "/dev/sr0") suitable for system commands like eject.
//
// Parameters:
//
//	driveSpec - the disc specification (e.g., "disc:0")
//
// Returns the corresponding device path (e.g., "/dev/sr0").
func extractDevicePath(driveSpec string) string {
	// Convert "disc:0" back to device path "/dev/sr0"
	// Extract the numeric index from the drive specification
	re := regexp.MustCompile(`\d+`)
	driveIndex := re.FindString(driveSpec)
	return fmt.Sprintf("/dev/sr%s", driveIndex)
}
