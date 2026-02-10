# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- Configuration system with `~/.rip.conf` file
  - Automatically creates `~/.rip.conf` on first run with defaults
  - Allows users to customize `storage_path` without rebuilding
  - Config file is human-readable and well-commented
  - Default storage path is `/plex/storage` (MergerFS mount point)
  - Supports tilde expansion (`~/path/to/media`)
- macOS and Linux device path support
  - macOS: `/dev/rdisk6` → `dev:/dev/rdisk6` for MakeMKV
  - Linux: `/dev/sr0` → `disc:0` for MakeMKV
  - Automatic platform detection based on device path
  - Added `formatDriveForMakeMKV()` function for device formatting
- Version management system
  - `-v` and `--version` flags show the current version
  - `rip version` command shows version information
  - Version is automatically injected at build time via ldflags
  - Versions match git tags (e.g., v0.1.0)
  - Patch version automatically increments on each `make release`
- Version script (`scripts/next-version.sh`)
  - Calculates next patch version based on current git tags
  - Used by Makefile to increment version automatically
- FileBot integration for movie/show name lookup and verification
  - When using `-m "movie name"` or specifying a show name, FileBot now looks up the correct name and year from TMDB/TheTVDB
  - Falls back to user-provided name if FileBot lookup fails
- CamelCase directory naming
  - Directory names are now formatted in CamelCase with no spaces (e.g., `TheMatrix1999` instead of `The Matrix (1999)`)
  - Improves consistency and eliminates issues with special characters in directory names
- Helper function `toCamelCase()` for consistent string formatting across DVD and TV commands

### Changed
- Output directory is now configurable via `~/.rip.conf` instead of hardcoded `/plex/storage`
- Device path handling now supports multiple platforms (Linux and macOS)
- Both DVD and TV commands now verify storage path is accessible and writable before ripping
- Improved error messages when storage path is invalid or inaccessible

### Fixed
- Improved error handling and logging in DVD ripping workflow
  - MakeMKV errors are now properly captured and displayed
  - Added detailed progress messages during title detection
  - Added MakeMKV output logging for debugging failed rips
  - Fatal error on MakeMKV failure instead of silently continuing

## [0.1.0] - 2026-01-18

### Added
- Business Source License (BSL 1.1) for commercial use protection while allowing free personal use
- Enhanced README documentation with detailed Plex/Jellyfin library setup instructions
- New "Organizing Categories in Plex/Jellyfin" section explaining how the `-c` category flag maps to directories
- Step-by-step guides for setting up separate media libraries in both Plex and Jellyfin
- Visual directory structure example showing how categories organize files
- `release` target in Makefile to build all platforms and create release binaries
- FileBot pricing information in dependencies section ($6/year or $50 lifetime)
- `release/` directory to .gitignore

### Changed
- Reorganized README structure: moved "Setting Up MergerFS" section after Install section
- Enhanced `-c, --category` parameter documentation to clarify directory mapping
- Updated MergerFS section with cross-references to detailed setup instructions
- Updated repository references from `rip` to `rip` in clone commands

### Technical
- Added RELEASE_DIR variable to Makefile for release builds
- Release target copies binaries from `binaries/<os>/rip` to `release/rip-<os>` with appropriate naming

---

## Format Notes

This changelog follows the [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) format.

Sections used:
- **Added** for new features
- **Changed** for changes in existing functionality
- **Deprecated** for soon-to-be removed features
- **Removed** for now removed features
- **Fixed** for any bug fixes
- **Security** for security-related fixes
