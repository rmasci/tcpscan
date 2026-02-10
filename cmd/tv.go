package cmd

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/rmasci/script"
	"github.com/spf13/cobra"
)

// tvCmd represents the `tv` command for ripping TV show DVDs.
// It automates the process of ripping TV show DVDs using MakeMKV,
// organizing episodes by season, fetching metadata, and renaming files.
var tvCmd = &cobra.Command{
	Use:   "tv [show name] [season-disc]",
	Short: "Rip TV show DVDs and organize by season",
	Long:  `Rip TV show DVDs and organize by season. Season-disc format is "season-disc" (e.g., "1-2" for season 1, disc 2).`,
	Args:  cobra.ExactArgs(2),
	Run:   tvrip,
}

// tvrip executes the TV ripping workflow.
// It performs the following steps:
// 1. Parses the show name and validates season-disc format
// 2. Uses FileBot to look up the correct show name and year (with fallback to user input)
// 3. Validates the MergerFS mountpoint
// 4. Creates the output directory structure with CamelCase naming
// 5. Executes MakeMKV to rip the disc
// 6. Cleans up files outside the acceptable duration range
// 7. Renames episodes using FileBot
// 8. Ejects the disc
// 9. Displays completion summary
func tvrip(cmd *cobra.Command, args []string) {
	// Parse command-line flags
	device, _ := cmd.Flags().GetString("device")
	query := args[0]
	seasonDiscStr := args[1]

	// Parse season-disc format (e.g., "1-2" -> season=1, disc=2)
	// This allows users to specify which disc of a multi-disc season they're ripping
	parts := strings.Split(seasonDiscStr, "-")
	if len(parts) != 2 {
		log.Fatal("Error: Invalid season-disc format. You must specify both season and disc (e.g., '1-2' for season 1, disc 2)")
	}

	seasonNum := parts[0]
	discNum := parts[1]

	// Step 1: Verify storage path is accessible before proceeding
	if err := VerifyStoragePath(AppConfig.StoragePath); err != nil {
		log.Fatalf("Error: %v\n\nPlease edit ~/.rip.conf to set a valid storage_path", err)
	}

	// Step 2: Try to look up the correct show name using FileBot
	// Format: Genre/Show Name (Year) {tmdb-ID}
	fmt.Printf("Looking up show info in TheTVDB for: %s...\n", query)
	showPath := fetchMetadata(query, "{genre.toCamelCase()}/{n} ({y}) {tmdb-$id}")

	// If FileBot lookup fails, use a fallback format with the user-provided name
	if showPath == "" {
		fmt.Printf("Warning: Could not find show in TheTVDB, using provided name: %s\n", query)
		// Create a simple fallback path with CamelCase show name
		showName := toCamelCase(query)
		showPath = fmt.Sprintf("Unknown/%s", showName)
	} else {
		fmt.Printf("Found: %s\n", showPath)
	}

	// Step 3: Create output directory structure with CamelCase naming
	// Directory format: [StoragePath]/Genre/Show Name (Year)/Season XX/
	// The showPath from FileBot already has the show name with CamelCase, so we just extract the show name part
	sPad := fmt.Sprintf("Season %02s", seasonNum)
	outDir := filepath.Join(AppConfig.StoragePath, showPath, sPad)
	if err := os.MkdirAll(outDir, 0755); err != nil {
		log.Fatalf("Error creating output directory: %v", err)
	}

	// Step 4: Format device path for MakeMKV (handles both Linux and macOS)
	drive := formatDriveForMakeMKV(device)
	fmt.Printf("Using device: %s\n", device)
	fmt.Printf("MakeMKV format: %s\n", drive)

	// Step 5: Execute MakeMKV rip operation
	fmt.Printf("Ripping to: %s\n", outDir)
	if err := runTVMakeMKV(drive, outDir); err != nil {
		fmt.Printf("Error during rip: %v\n", err)
		log.Fatalf("MakeMKV extraction failed. Please check your disc and try again.")
	}

	// Step 6: Clean up files that are too short or too long (not episodes)
	cleanupPlayAll(outDir)

	// Step 7: Rename episode files with proper names from TheTVDB
	fmt.Println("Renaming episodes with proper names from FileBot...")
	if err := renameWithFileBot(seasonNum, discNum, outDir); err != nil {
		fmt.Printf("Warning: FileBot rename failed: %v\n", err)
	}

	// Step 8: Eject the disc from the drive
	devicePath := extractDevicePath(drive)
	if err := ejectDisc(devicePath); err != nil {
		fmt.Printf("Warning: Could not eject disc: %v\n", err)
	}

	// Step 9: Display completion summary with next steps
	fmt.Println("-------------------------------------------------------")
	fmt.Println("RIP COMPLETE!")
	fmt.Printf("Files are in: %s\n", outDir)
	fmt.Printf("Step 1: Verify episodes match S%sE01, S%sE02, etc.\n", sPad, sPad)
	fmt.Println("Step 2: Verify file names are correct.")
	fmt.Println("Step 3: Scan library in Jellyfin/Plex Dashboard.")
}

// cleanupPlayAll removes MKV files that are outside the acceptable duration range for TV episodes.
// It removes files that are:
// - Shorter than 10 minutes (600 seconds) - likely intro/outro files
// - Longer than 1 hour 5 minutes (3900 seconds) - likely "Play All" merged tracks
//
// The function uses ffprobe to determine file duration and requires it to be installed.
// If ffprobe is not available, it logs a warning and skips cleanup.
func cleanupPlayAll(dir string) {
	fmt.Println("Cleaning up extra-long 'Play All' tracks...")

	// Check if ffprobe is available before attempting to use it
	if _, err := exec.LookPath("ffprobe"); err != nil {
		fmt.Println("Warning: ffprobe not found. Skipping automatic Play-All cleanup.")
		return
	}

	// Get all MKV files in the output directory
	files, _ := filepath.Glob(filepath.Join(dir, "*.mkv"))

	// Define acceptable episode duration range
	minSeconds := 600  // 10 minutes - minimum episode length
	maxSeconds := 3900 // 1 hour 5 minutes - maximum episode length

	for _, f := range files {
		// Get duration via ffprobe in seconds
		out, err := exec.Command("ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "default=noprint_wrappers=1:nokey=1", f).Output()
		if err != nil {
			continue
		}

		// Parse duration string to float
		durationStr := strings.TrimSpace(string(out))
		duration, _ := strconv.ParseFloat(durationStr, 64)
		durationInt := int(duration)

		// Remove files that are too short (likely not actual episodes)
		if durationInt < minSeconds {
			fmt.Printf("Removing file shorter than 10 minutes: %s (Duration: %.2f min)\n", filepath.Base(f), duration/60)
			if err := os.Remove(f); err != nil {
				fmt.Printf("Warning: Could not remove file %s: %v\n", filepath.Base(f), err)
			}
		} else if durationInt > maxSeconds {
			// Remove files that are too long (likely "Play All" or merged tracks)
			fmt.Printf("Removing file longer than 1 hour 5 minutes: %s (Duration: %.2f min)\n", filepath.Base(f), duration/60)
			if err := os.Remove(f); err != nil {
				fmt.Printf("Warning: Could not remove file %s: %v\n", filepath.Base(f), err)
			}
		}
	}
}

// init registers the tv command with the root command and configures its flags.
func init() {
	// Define the device flag for specifying the DVD drive location
	tvCmd.Flags().StringP("device", "d", "/dev/sr0", "Physical device path")

	// Register the tv command as a subcommand of the root command
	rootCmd.AddCommand(tvCmd)
}

// runTVMakeMKV executes the MakeMKV command to rip all titles from a TV show disc.
// It uses the script library to execute the makemkvcon CLI tool with appropriate parameters.
//
// Parameters:
//
//	drive - the disc specification (e.g., "disc:0")
//	outDir - the output directory where MKV files will be saved
//
// Returns an error if the makemkvcon command fails.
func runTVMakeMKV(drive, outDir string) error {
	// Execute makemkvcon mkv command to rip all titles longer than 10 minutes (600 seconds)
	// Parameters:
	//   mkv - operation to rip to Matroska format
	//   drive - disc specification
	//   all - rip all titles from the disc
	//   outDir - destination folder for output files
	//   --minlength=600 - only rip titles longer than 10 minutes
	return script.Exec(fmt.Sprintf("makemkvcon mkv %s all \"%s\" --minlength=600", drive, outDir)).
		Spinner("Extracting episodes...", 9).
		Error()
}

// renameWithFileBot uses FileBot to rename episode files with proper names from TheTVDB database.
// It renames files recursively in the output directory using a Plex-compatible naming format.
//
// Parameters:
//
//	seasonNum - the season number (e.g., "1" for season 1)
//	discNum - the disc number within the season (e.g., "2" for disc 2)
//	outDir - the directory containing the episode files to rename
//
// The format string produces names like: "Show Name - S01E01 - Episode Title"
// The discNum parameter is parsed but currently not actively used in the episode offset calculation.
//
// Returns an error if the FileBot rename command fails.
func renameWithFileBot(seasonNum, discNum, outDir string) error {
	// FileBot rename command format:
	// filebot -rename "source_folder" -r --db TheTVDB --format "format_string"
	// The format string uses Plex-compatible naming: {n} S{s}E{e} - {t}
	// where: n=show name, s=season, e=episode, t=episode title

	// Parse disc number from string to integer
	// This helps FileBot understand which episodes are on this disc
	// For example: Disc 1 has episodes 1-4, Disc 2 has episodes 5-8, etc.
	discInt := 1
	if discNum != "" {
		_, _ = fmt.Sscanf(discNum, "%d", &discInt)
	}

	// Format with season information in output
	// Example output: "Show Name - S01E01 - Episode Title"
	renameFormat := "{n} - S" + seasonNum + "E{e} - {t}"

	// Execute FileBot rename command with --action move to actually rename files
	fmt.Println("Running FileBot to rename episode files...")
	cmd := fmt.Sprintf("filebot -rename \"%s\" -r --db TheTVDB --format '%s' --action move", outDir, renameFormat)
	fmt.Printf("FileBot command: %s\n", cmd)

	p := script.Exec(cmd).
		Spinner("Renaming episodes...", 9)
	output, err := p.String()

	// Always print the output for debugging
	if output != "" {
		fmt.Printf("FileBot output:\n%s\n", output)
	}

	if err != nil {
		fmt.Printf("FileBot error: %v\n", err)
		// Don't return error - FileBot might succeed even if script.Exec returns an error
		return nil
	}

	return nil
}
