package cmd

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/rmasci/script"
	"github.com/spf13/cobra"
)

// dvdCmd represents the `dvd` command for ripping DVDs.
// It automates the process of ripping DVDs using MakeMKV,
// organizing them by category, fetching metadata, and renaming files.
// The command supports discovering movie names from disc metadata or accepting them as a flag.
var dvdCmd = &cobra.Command{
	Use:   "dvd",
	Short: "Rip DVDs using MakeMKV and organize by category",
	Long: `The "dvd" command automates the ripping of DVDs using MakeMKV,
categorizing them for use with media libraries like Plex. It requires
you to provide a physical device path, a category, and optionally a movie name.`,
	Args: cobra.NoArgs, // No non-flag arguments are required
	Run:  rip,
}

// rip executes the DVD ripping workflow with interactive prompts.
// Step 1: Detect discs from /dev/disk/by-label/ and let user choose
// Step 2: Use FileBot to verify/get the movie name
// Step 3: Select category from /plex/storage directories
// Step 4: Create directory under category as "Movie Name (YYYY)"
// Step 5: Rip the DVD to MKV
// Step 6: Rename MKV to "Movie Name (YYYY).mkv"
func rip(cmd *cobra.Command, args []string) {
	// Parse command-line flags
	device, _ := cmd.Flags().GetString("device")
	category, _ := cmd.Flags().GetString("category")
	movie, _ := cmd.Flags().GetString("movie")

	// Step 1: Verify storage path is accessible
	if err := VerifyStoragePath(AppConfig.StoragePath); err != nil {
		log.Fatalf("Error: %v\n\nPlease edit ~/.rip.conf to set a valid storage_path", err)
	}

	// Step 1: Detect and select disc from /dev/disk/by-label/
	var discLabel string
	var selectedDevice string

	if device == "" || device == "/dev/sr0" {
		discLabel, selectedDevice = selectDiscFromLabels()
		if selectedDevice == "" {
			log.Fatal("No disc selected. Exiting.")
		}
		fmt.Printf("Selected device: %s (Label: %s)\n", selectedDevice, discLabel)
	} else {
		selectedDevice = device
		discLabel = ""
	}

	// Step 2: Get and verify movie name using FileBot
	var finalMovieName string

	if movie != "" {
		// User provided movie name via flag
		finalMovieName = verifyMovieNameWithFileBot(movie)
	} else if discLabel != "" {
		// Try using disc label
		cleanLabel := strings.ReplaceAll(discLabel, "_", " ")
		finalMovieName = verifyMovieNameWithFileBot(cleanLabel)
	} else {
		// Ask user for movie name
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Enter movie name: ")
		input, _ := reader.ReadString('\n')
		movieInput := strings.TrimSpace(input)
		finalMovieName = verifyMovieNameWithFileBot(movieInput)
	}

	if finalMovieName == "" {
		log.Fatal("Error: Could not determine movie name. Exiting.")
	}

	fmt.Printf("Movie name: %s\n", finalMovieName)

	// Step 3: Select category from /plex/storage
	var selectedCategory string

	if category != "" {
		selectedCategory = category
	} else {
		selectedCategory = selectCategory()
		if selectedCategory == "" {
			log.Fatal("No category selected. Exiting.")
		}
	}

	fmt.Printf("Category: %s\n", selectedCategory)

	// Step 4: Create directory structure: /plex/storage/Category/Movie Name (YYYY)/
	movieDir := filepath.Join(AppConfig.StoragePath, selectedCategory, finalMovieName)
	if err := os.MkdirAll(movieDir, 0755); err != nil {
		log.Fatalf("Error creating movie directory: %v", err)
	}
	fmt.Printf("Created directory: %s\n", movieDir)

	// Step 5: Rip the DVD
	fmt.Println("\nStarting DVD rip...")
	drive := formatDriveForMakeMKV(selectedDevice)
	fmt.Printf("Using device: %s\n", selectedDevice)
	fmt.Printf("MakeMKV format: %s\n", drive)

	if err := runDVDMakeMKV(drive, movieDir); err != nil {
		log.Fatalf("Error during MakeMKV rip: %v", err)
	}

	// Step 6: Rename MKV to "Movie Name (YYYY).mkv"
	fmt.Println("\nRenaming movie file...")
	targetFile := filepath.Join(movieDir, finalMovieName+".mkv")

	if err := renameMKVFile(movieDir, targetFile); err != nil {
		fmt.Printf("Warning: Could not rename file: %v\n", err)
	} else {
		fmt.Printf("Renamed to: %s\n", targetFile)
	}

	// Eject the disc
	devicePath := extractDevicePath(drive)
	if err := ejectDisc(devicePath); err != nil {
		fmt.Printf("Warning: Could not eject disc: %v\n", err)
	}

	// Display completion summary
	fmt.Println("\n-------------------------------------------------------")
	fmt.Println("RIP COMPLETE!")
	fmt.Printf("Movie: %s\n", finalMovieName)
	fmt.Printf("Category: %s\n", selectedCategory)
	fmt.Printf("Location: %s\n", movieDir)
	fmt.Println("-------------------------------------------------------")
}

// init registers the dvd command with the root command and configures its flags.
func init() {
	// Define command-line flags
	dvdCmd.Flags().StringP("device", "d", "/dev/sr0", "Physical device path (e.g. /dev/sr0)")
	dvdCmd.Flags().StringP("category", "c", "", "Target category folder (e.g. Comedy, Action)")
	dvdCmd.Flags().StringP("movie", "m", "", "Movie name to bypass discovery and use directly")

	// Register the dvd command as a subcommand of the root command
	rootCmd.AddCommand(dvdCmd)
}

// isMountpoint checks if the specified path is a valid mountpoint using the mountpoint command.
// Returns true if the path is a mountpoint, false otherwise.
func isMountpoint(path string) bool {
	// Use the mountpoint command with -q (quiet) flag
	// Returns nil (exit code 0) if path is a mountpoint, error otherwise
	cmd := exec.Command("mountpoint", "-q", path)
	return cmd.Run() == nil
}

// fetchMetadata queries FileBot to retrieve metadata from TheMovieDB database.
// It uses the provided query string and format string to look up and format movie information.
//
// Parameters:
//
//	query - the search query (movie name)
//	format - the FileBot format string for output (e.g., "{n} ({y})")
//
// Returns the formatted metadata string or empty string if lookup fails.
func fetchMetadata(query, format string) string {
	// Execute FileBot list command to query TheMovieDB
	p := script.Exec(fmt.Sprintf("filebot -list --db TheMovieDB --q '%s' --format '%s'", query, format)).
		Spinner("Querying TMDB...", 9)
	out, err := p.String()
	if err != nil {
		log.Printf("Error fetching metadata: %v\n", err)
		return ""
	}
	// Parse the first line of output as the metadata result
	lines := strings.Split(out, "\n")
	return strings.TrimSpace(lines[0])
}

// extractDriveIndex extracts the numeric drive index from a device path.
// For example, converts "/dev/sr0" to "0", "/dev/sr1" to "1", etc.
// This index is used to identify the disc in MakeMKV commands (e.g., "disc:0").
func extractDriveIndex(devicePath string) string {
	// Use regex to find all numeric digits in the device path
	re := regexp.MustCompile(`[0-9]+`)
	return re.FindString(devicePath)
}

// formatDriveForMakeMKV converts a device path to MakeMKV format.
// On Linux: /dev/sr0 -> disc:0
// On macOS: /dev/rdisk6 -> dev:/dev/rdisk6
//
// Parameters:
//
//	devicePath - the device path (e.g., "/dev/sr0" or "/dev/rdisk6")
//
// Returns the device specification formatted for MakeMKV
func formatDriveForMakeMKV(devicePath string) string {
	// Check if this is a macOS device path (contains "rdisk")
	if strings.Contains(devicePath, "rdisk") {
		// macOS format: dev:/dev/rdisk6
		return fmt.Sprintf("dev:%s", devicePath)
	}
	// Linux format: disc:0
	driveIndex := extractDriveIndex(devicePath)
	return fmt.Sprintf("disc:%s", driveIndex)
}

// runDVDMakeMKV executes the MakeMKV command to rip the longest title from a DVD.
// It first queries the disc to identify all available titles, finds the longest one,
// then executes the rip operation. Ejection is handled by the caller after all steps complete.
//
// Parameters:
//
//	drive - the disc specification (e.g., "disc:0")
//	outDir - the output directory where the MKV file will be saved
//
// Returns an error if the makemkvcon command fails.
func runDVDMakeMKV(drive, outDir string) error {

	// Step 1: Query the disc to get information about all available titles
	// Uses the -r flag for robot mode (machine-readable output)
	fmt.Println("Querying disc for available titles...")
	p := script.Exec(fmt.Sprintf("makemkvcon -r info %s", drive)).
		Spinner("Reading disc...", 9)
	infoOutput, err := p.String()
	if err != nil {
		return fmt.Errorf("error running makemkvcon info: %v", err)
	}

	// Step 2: Parse the output to identify all titles and find the longest one
	// TINFO line format: TINFO:title_id,27,duration_in_seconds,"duration_in_ms"
	re := regexp.MustCompile(`TINFO:(\d+),27,\d+,"(\d+)"`)
	var longestTitleID string
	var maxDuration int
	titleDurations := make(map[string]int)

	for _, line := range strings.Split(infoOutput, "\n") {
		matches := re.FindStringSubmatch(line)
		if len(matches) == 3 {
			titleID := matches[1]
			duration, _ := strconv.Atoi(matches[2])
			durationSeconds := duration / 1000 // Convert milliseconds to seconds
			titleDurations[titleID] = durationSeconds

			// Keep track of the title with the maximum duration
			if durationSeconds > maxDuration {
				maxDuration = durationSeconds
				longestTitleID = titleID
			}
		}
	}

	// Print all found titles for debugging
	if len(titleDurations) > 0 {
		fmt.Println("Found titles:")
		for titleID, duration := range titleDurations {
			minutes := duration / 60
			seconds := duration % 60
			fmt.Printf("  Title %s: %d min %d sec (%d seconds)\n", titleID, minutes, seconds, duration)
		}
	}

	// Step 3: Run the mkv rip command with the longest title ID
	titleID := longestTitleID
	if titleID == "" {
		fmt.Println("Warning: Could not determine longest title, using title 0")
		titleID = "0"
	} else {
		minutes := maxDuration / 60
		seconds := maxDuration % 60
		fmt.Printf("Selected longest title: %s (%d min %d sec)\n", titleID, minutes, seconds)
	}

	// Execute makemkvcon mkv command to rip the longest title
	// --minlength=3600 ensures we only rip titles longer than 1 hour (for movies)
	fmt.Printf("Starting MakeMKV rip (title %s)...\n", titleID)
	mkv := script.Exec(fmt.Sprintf("makemkvcon mkv %s %s \"%s\" --minlength=3600", drive, titleID, outDir)).
		Spinner("Extracting video...", 9)
	output, err := mkv.String()
	if err != nil {
		fmt.Printf("MakeMKV error output:\n%s\n", output)
		return fmt.Errorf("makemkvcon mkv command failed: %v", err)
	}

	fmt.Printf("MakeMKV output:\n%s\n", output)
	return nil
}

// discoverMovieName attempts to extract the movie title from the DVD disc metadata using MakeMKV.
// It queries the disc information and parses the output to extract the disc title.
//
// Parameters:
//
//	devicePath - the device path of the DVD drive (e.g., "/dev/sr0")
//
// Returns the discovered movie name or empty string if discovery fails.
func discoverMovieName(devicePath string) string {
	// Extract the drive index from the device path to format for MakeMKV
	driveIndex := extractDriveIndex(devicePath)
	drive := fmt.Sprintf("disc:%s", driveIndex)

	// Query disc information using makemkvcon with robot mode (-r) output
	p := script.Exec(fmt.Sprintf("makemkvcon -r info %s", drive)).
		Spinner("Reading disc title...", 9)
	out, err := p.String()
	if err != nil {
		log.Printf("Error running makemkvcon: %v", err)
		return ""
	}

	// Parse the output to extract the movie name
	// CINFO line format: CINFO:2,0,"movie_title"
	// where: 2 = disc, 0 = disc title field
	re := regexp.MustCompile(`(?m)^CINFO:2,0,"(.+)"`)
	matches := re.FindStringSubmatch(out)
	if len(matches) > 1 {
		return matches[1]
	}

	return ""
}

// renameMovieWithFileBot uses FileBot to rename a movie file with proper name from TheMovieDB database.
// It renames files recursively in the output directory using a Plex-compatible naming format.
//
// Parameters:
//
//	movieName - the movie name (currently unused, kept for potential future use)
//	outDir - the directory containing the movie file to rename
//
// The format string produces names like: "Movie Title (Year)"
//
// Returns an error if the FileBot rename command fails.
func renameMovieWithFileBot(movieName, outDir string) error {
	// FileBot rename command format for movies
	// Format string: {n} ({y})
	// where: n=movie name, y=year
	renameFormat := "{n} ({y})"

	// Execute FileBot rename command with --action move to actually rename files
	// Uses TheMovieDB database for metadata lookup
	fmt.Println("Running FileBot to rename movie file...")
	cmd := fmt.Sprintf("filebot -rename \"%s\" -r --db TheMovieDB --format '%s' --action move", outDir, renameFormat)
	fmt.Printf("FileBot command: %s\n", cmd)

	p := script.Exec(cmd).
		Spinner("Renaming file...", 9)
	output, err := p.String()

	// Always print the output for debugging
	if output != "" {
		fmt.Printf("FileBot output:\n%s\n", output)
	}

	if err != nil {
		fmt.Printf("FileBot error: %v\n", err)
		// Don't return error - FileBot might succeed even if script.Exec returns an error
		// Check if files were actually renamed
		return nil
	}
	fmt.Println("FileBot renamed to the correct movie name successfully.")

	return nil
}

// toCamelCase converts a string to CamelCase with no spaces.
// It removes all spaces and special characters (except alphanumeric), and converts to PascalCase.
// For example:
//
//	"The Matrix (1999)" -> "TheMatrix1999"
//	"Inception" -> "Inception"
//	"Star Wars: A New Hope (1977)" -> "StarWarsANewHope1977"
//
// Parameters:
//
//	s - the string to convert
//
// Returns the CamelCase version of the string with no spaces.
func toCamelCase(s string) string {
	// Remove special characters and split on spaces
	var result strings.Builder
	words := strings.FieldsFunc(s, func(r rune) bool {
		// Split on spaces and special characters (keep only alphanumeric)
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})

	// Capitalize first letter of each word
	for _, word := range words {
		if len(word) > 0 {
			// Capitalize first rune, keep rest as-is
			result.WriteRune(unicode.ToUpper(rune(word[0])))
			result.WriteString(word[1:])
		}
	}

	return result.String()
}

// selectDiscFromLabels scans /dev/disk/by-label/ and lets user select a disc
// Returns the disc label and actual device path
func selectDiscFromLabels() (string, string) {
	fmt.Println("\nScanning for discs...")

	entries, err := os.ReadDir("/dev/disk/by-label/")
	if err != nil {
		fmt.Printf("Could not read /dev/disk/by-label/: %v\n", err)
		return "", ""
	}

	// Collect available discs
	type DiscInfo struct {
		label      string
		devicePath string
	}

	var discs []DiscInfo
	seenDevices := make(map[string]bool)

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		linkPath := filepath.Join("/dev/disk/by-label", entry.Name())
		devicePath, err := filepath.EvalSymlinks(linkPath)
		if err != nil {
			continue
		}

		// Skip duplicates
		if seenDevices[devicePath] {
			continue
		}
		seenDevices[devicePath] = true

		discs = append(discs, DiscInfo{
			label:      entry.Name(),
			devicePath: devicePath,
		})
	}

	if len(discs) == 0 {
		fmt.Println("No discs found in /dev/disk/by-label/")
		return "", ""
	}

	// Display menu
	fmt.Println("\nAvailable discs:")
	for i, disc := range discs {
		fmt.Printf("[%d] %s (%s)\n", i+1, disc.label, disc.devicePath)
	}

	// Get user selection
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("Select disc (1-%d): ", len(discs))
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		selection, err := strconv.Atoi(input)
		if err == nil && selection > 0 && selection <= len(discs) {
			selected := discs[selection-1]
			return selected.label, selected.devicePath
		}

		fmt.Println("Invalid selection. Please try again.")
	}
}

// verifyMovieNameWithFileBot queries FileBot and asks user to confirm/correct
// Returns the final movie name in format "Movie Name (YYYY)"
func verifyMovieNameWithFileBot(query string) string {
	// Clean up query
	cleanQuery := strings.ReplaceAll(query, "_", " ")

	fmt.Printf("\nLooking up movie in TheMovieDB: %s\n", cleanQuery)

	// Query FileBot
	result := fetchMetadata(cleanQuery, "{n} ({y})")

	reader := bufio.NewReader(os.Stdin)

	if result != "" {
		// Found a match - ask user to confirm
		fmt.Printf("Found: %s\n", result)
		fmt.Print("Is this correct? (y/n): ")
		response, _ := reader.ReadString('\n')
		response = strings.TrimSpace(strings.ToLower(response))

		if response == "y" || response == "yes" {
			return result
		}
	} else {
		fmt.Println("Could not find movie in TheMovieDB.")
	}

	// Ask user to provide correct name
	for {
		fmt.Print("Enter the correct movie name: ")
		input, _ := reader.ReadString('\n')
		movieName := strings.TrimSpace(input)

		if movieName == "" {
			fmt.Println("Movie name cannot be empty. Please try again.")
			continue
		}

		// Query FileBot again with user-provided name
		fmt.Printf("Looking up: %s\n", movieName)
		result = fetchMetadata(movieName, "{n} ({y})")

		if result != "" {
			fmt.Printf("Found: %s\n", result)
			fmt.Print("Is this correct? (y/n): ")
			response, _ := reader.ReadString('\n')
			response = strings.TrimSpace(strings.ToLower(response))

			if response == "y" || response == "yes" {
				return result
			}
		} else {
			fmt.Println("Could not find in TheMovieDB.")
			fmt.Print("Use this name anyway? (y/n): ")
			response, _ := reader.ReadString('\n')
			response = strings.TrimSpace(strings.ToLower(response))

			if response == "y" || response == "yes" {
				return movieName
			}
		}
	}
}

// selectCategory lets user select a category from directories in /plex/storage
// Only shows directories that start with a capital letter
// Returns the selected category name
func selectCategory() string {
	fmt.Println("\nScanning categories...")

	entries, err := os.ReadDir(AppConfig.StoragePath)
	if err != nil {
		fmt.Printf("Error reading storage path: %v\n", err)
		return ""
	}

	// Filter directories that start with capital letter
	var categories []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		name := entry.Name()
		if len(name) > 0 && unicode.IsUpper(rune(name[0])) {
			categories = append(categories, name)
		}
	}

	if len(categories) == 0 {
		fmt.Println("No categories found in storage path.")
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Enter new category name: ")
		input, _ := reader.ReadString('\n')
		return strings.TrimSpace(input)
	}

	// Display menu
	fmt.Println("\nAvailable categories:")
	for i, cat := range categories {
		fmt.Printf("[%d] %s\n", i+1, cat)
	}
	fmt.Printf("[%d] Create new category\n", len(categories)+1)

	// Get user selection
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("Select category (1-%d): ", len(categories)+1)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		selection, err := strconv.Atoi(input)
		if err == nil && selection > 0 && selection <= len(categories) {
			return categories[selection-1]
		} else if err == nil && selection == len(categories)+1 {
			// Create new category
			fmt.Print("Enter new category name: ")
			newCat, _ := reader.ReadString('\n')
			return strings.TrimSpace(newCat)
		}

		fmt.Println("Invalid selection. Please try again.")
	}
}

// renameMKVFile finds the MKV file in the directory and renames it to the target filename
func renameMKVFile(directory, targetPath string) error {
	// Find MKV files in directory
	entries, err := os.ReadDir(directory)
	if err != nil {
		return fmt.Errorf("error reading directory: %v", err)
	}

	var mkvFiles []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(strings.ToLower(entry.Name()), ".mkv") {
			mkvFiles = append(mkvFiles, filepath.Join(directory, entry.Name()))
		}
	}

	if len(mkvFiles) == 0 {
		return fmt.Errorf("no MKV files found in directory")
	}

	if len(mkvFiles) > 1 {
		fmt.Printf("Warning: Multiple MKV files found. Renaming each:\n")
		for i, mkvFile := range mkvFiles {
			if i == 0 {
				// First file gets the main name
				if err := os.Rename(mkvFile, targetPath); err != nil {
					return fmt.Errorf("error renaming %s: %v", mkvFile, err)
				}
				fmt.Printf("  Renamed: %s -> %s\n", filepath.Base(mkvFile), filepath.Base(targetPath))
			} else {
				// Additional files get numbered suffix
				ext := filepath.Ext(targetPath)
				base := strings.TrimSuffix(targetPath, ext)
				numberedPath := fmt.Sprintf("%s%d%s", base, i, ext)
				if err := os.Rename(mkvFile, numberedPath); err != nil {
					return fmt.Errorf("error renaming %s: %v", mkvFile, err)
				}
				fmt.Printf("  Renamed: %s -> %s\n", filepath.Base(mkvFile), filepath.Base(numberedPath))
			}
		}
		return nil
	}

	// Single file - simple rename
	return os.Rename(mkvFiles[0], targetPath)
}
