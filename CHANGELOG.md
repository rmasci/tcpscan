# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.2] - 2026-02-13

### Changed
- **Project Layout Cleanup**: Removed legacy root-level `.go` files (`tcpscan.go`, `tcpCheck.go`, `tcpCheckw.go`, `format.go`, `digicert.go`, `subnetcalc.go`, `traceroute.go`, `setFilesLinux.go`, `setFilesWindows.go`, `test.go`) that were superseded by the `cmd/tcpscan/` + `internal/` refactor
- Moved documentation files from `cmd/tcpscan/` to `docs/` directory
- Moved `CHANGELOG.md` from `cmd/tcpscan/` to project root (standard location)
- Removed committed binaries (`tcpscan`, `build/tcpscan`) from version control
- Removed stale files (`README.md.old`, `usage.md`, `iplist.txt`, `.project`, `tcpscan.komodoproject`)
- Updated `.gitignore` to cover IDE project files (`.project`, `*.komodoproject`)
- Fixed `go vet` warning in `printExtendedUsage` (redundant newline in `fmt.Println`)

## [2.1.1] - 2026-02-05

### Fixed
- **Windows Cross-Compilation**: Fixed build failure when cross-compiling for Windows caused by `github.com/tevino/tcp-shaker` dependency using `golang.org/x/sys/unix`
- Split scanner into platform-specific files using build tags:
  - `scanner_unix.go` (`//go:build !windows`): Uses tcp-shaker for fast SYN-only TCP checks
  - `scanner_windows.go` (`//go:build windows`): Uses standard `net.Dial` for TCP checks
- Windows builds now complete successfully with `make win64`

## [2.1.0] - 2026-01-23

### Added - User-Friendly Features
- **Service Presets** (`--check`): Pre-configured service checks (web, database, ssh, mail, dns, ldap, rdp, smb)
- **Diagnostic Hints** (default): Automatic suggestions when connections fail
- **Plain English Explanations** (`--explain`): Detailed, easy-to-understand result explanations
- **Connection Quality Metrics** (`--samples N`): Test reliability with multiple connection attempts
- **Smart Suggestions**: Context-aware next steps based on scan results

### Added - Build System
- **Release Target** (`make release`): Automated release workflow that increments patch version, creates git tag, pushes tag, and builds all platform binaries

### Changed
- Hints are now enabled by default (disable with `--hints=false`)
- Verbose flag changed from `-v` to `-V` (capital V)
- Version flag now uses `-v` (lowercase v)

### Documentation
- Added USER_FEATURES.md with comprehensive guide for non-technical users
- Updated README.md with new features and examples
- Added real-world troubleshooting scenarios
- Added release process documentation in README.md

## [2.0.0] - 2026-01-23

### Added
- Modern internal package structure (`internal/types`, `internal/scanner`, `internal/parser`, `internal/output`, `internal/coordinator`)
- Context-based cancellation support throughout the application
- Proper error wrapping with `fmt.Errorf` and `%w` verb
- Concurrent scan limiting (512 goroutines max) using `errgroup.SetLimit`
- Strong typing with `PortStatus` type and constants
- Structured configuration via `types.Config` struct
- Modern Makefile with `deps`, `test`, `lint`, and `install` targets
- Build tags for platform-specific code (`setfiles_unix.go`, `setfiles_windows.go`)
- Comprehensive documentation (`MODERNIZATION.md`, `MIGRATION_GUIDE.md`)

### Changed
- **BREAKING (Internal):** Moved from single-file to multi-package architecture
- Updated Go version from 1.17 to 1.21+
- Replaced global variables with configuration struct
- Migrated from manual goroutine tracking to `golang.org/x/sync/errgroup`
- Improved error handling with proper error wrapping and context
- Refactored concurrency patterns for better control and error propagation
- Moved main entry point from root `tcpscan.go` to `cmd/tcpscan/main.go`
- Updated dependency management to use `jf go mod tidy` convention
- Improved code organization with separation of concerns

### Improved
- Error messages now include full context chain
- Better IDE support with proper type definitions
- Easier to test with separated packages
- More maintainable codebase with clear package boundaries
- Better performance with controlled concurrency
- Cleaner code with elimination of global state

### Maintained
- 100% CLI compatibility - all existing flags and options work identically
- All output formats (grid, CSV, Excel, text, tab)
- 2048 host/port scan limit (security feature)
- SSL certificate checking functionality
- DNS lookup functionality  
- ICMP ping support
- Subnet calculator
- Cross-platform support (Linux, macOS, Windows, BSD, Solaris)
- File input and piped input support
- Port range scanning
- Subnet scanning

### Technical Details
- Uses `golang.org/x/sync/errgroup` for concurrent operations
- Implements proper context propagation for cancellation
- Type-safe operations with custom types (`PortStatus`, `ScanTarget`, `ScanResult`)
- Structured error handling with error wrapping
- Platform-specific code using build tags
- Modern Go project layout following community standards

### Migration Notes
- Users: No changes needed - CLI is 100% compatible
- Developers: See `MIGRATION_GUIDE.md` for code structure changes
- Build: Use `make build` or `go build ./cmd/tcpscan`
- Original code preserved for reference

### Dependencies
- Added: `golang.org/x/sync v0.6.0` for errgroup
- Updated: All dependencies to latest compatible versions
- Maintained: All existing dependencies (gotabulate, ipsubnet, pflag, tcp-shaker, excelize)

## [1.8.15] - 2021-03-24

Previous version with Go 1.17 and single-file architecture.

### Features
- TCP port scanning
- SSL certificate validation
- DNS lookups
- ICMP ping checks
- Multiple output formats
- Subnet calculator
- Cross-platform support

---

## Version Comparison

| Feature | v1.8.15 | v2.0.0 |
|---------|---------|--------|
| Go Version | 1.17 | 1.21+ |
| Architecture | Single file | Multi-package |
| Concurrency | Manual channels | errgroup |
| Error Handling | Custom function | Wrapped errors |
| Configuration | Global vars | Config struct |
| Type Safety | Strings | Strong types |
| CLI Compatibility | ✅ | ✅ (100%) |
| Output Formats | ✅ | ✅ (Same) |
| Performance | Good | Better |
| Maintainability | Moderate | High |
| Testability | Low | High |
