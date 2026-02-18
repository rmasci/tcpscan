# Building TCPScan

## Quick Build

```bash
# Build all platform binaries (default)
make

# Binaries will be in ./release/
```

## Build Targets

### All Platforms (Default)
```bash
make
# or explicitly
make all
```

Builds for:
- macOS AMD64 (`tcpscan-mac`)
- macOS ARM64 (`tcpscan-mac-arm`)
- Linux AMD64 (`tcpscan-l64`)
- Linux ARM64 (`tcpscan-la64`)
- Windows AMD64 (`tcpscan-w64.exe`)
- Raspberry Pi (`tcpscan-pi`)
- OpenBSD AMD64 (`tcpscan-ob64`)
- NetBSD AMD64 (`tcpscan-net64`)
- FreeBSD AMD64 (`tcpscan-free64`)
- Solaris AMD64 (`tcpscan-sol`)

### Current Platform Only
```bash
make build
# Binary will be in ./build/tcpscan
```

### Specific Platform
```bash
make mac        # macOS AMD64
make mac-arm    # macOS ARM64 (Apple Silicon)
make linux64    # Linux AMD64
make linuxa64   # Linux ARM64
make win64      # Windows AMD64
make pi         # Raspberry Pi
make openbsd64  # OpenBSD AMD64
make netbsd64   # NetBSD AMD64
make freebsd64  # FreeBSD AMD64
make solaris    # Solaris AMD64
```

## Output Directories

| Directory | Purpose | Git Tracked |
|-----------|---------|-------------|
| `./release/` | All platform binaries | ❌ No (in .gitignore) |
| `./build/` | Current platform binary | ❌ No (in .gitignore) |

## Other Targets

### Update Dependencies
```bash
make deps
# Uses 'jf go mod tidy' per project convention
```

### Run Tests
```bash
make test
# Runs tests with race detector and coverage
```

### Run Linter
```bash
make lint
# Requires golangci-lint to be installed
```

### Install Locally
```bash
make install
# Installs to $GOPATH/bin
```

### Clean Build Artifacts
```bash
make clean
# Removes ./build/, ./release/, and coverage files
```

### Show Help
```bash
make help
```

## Direct Go Commands

If you prefer to use Go directly:

```bash
# Build for current platform
go build -o tcpscan ./cmd/tcpscan

# Build for specific platform
GOOS=linux GOARCH=amd64 go build -o tcpscan-linux ./cmd/tcpscan

# Install
go install ./cmd/tcpscan
```

## Binary Naming Convention

| Platform | Binary Name |
|----------|-------------|
| macOS AMD64 | `tcpscan-mac` |
| macOS ARM64 | `tcpscan-mac-arm` |
| Linux AMD64 | `tcpscan-l64` |
| Linux ARM64 | `tcpscan-la64` |
| Windows AMD64 | `tcpscan-w64.exe` |
| Raspberry Pi | `tcpscan-pi` |
| OpenBSD AMD64 | `tcpscan-ob64` |
| NetBSD AMD64 | `tcpscan-net64` |
| FreeBSD AMD64 | `tcpscan-free64` |
| Solaris AMD64 | `tcpscan-sol` |

## CI/CD Integration

For automated builds:

```bash
# Build all platforms
make

# Binaries are in ./release/ directory
# They are NOT committed to git (in .gitignore)
# Upload ./release/* to your release system
```

## Troubleshooting

### "make: command not found"
Install make for your platform:
- macOS: `xcode-select --install`
- Linux: `sudo apt-get install build-essential` (Debian/Ubuntu)
- Windows: Use WSL or install GNU Make

### "golangci-lint not found"
The linter is optional. Install from: https://golangci-lint.run/usage/install/

### Build fails with "permission denied"
Ensure you have write permissions to the `./release/` and `./build/` directories.

### Old binaries still present
Run `make clean` to remove all build artifacts.

## Development Workflow

```bash
# 1. Make code changes
vim cmd/tcpscan/main.go

# 2. Update dependencies if needed
make deps

# 3. Run tests
make test

# 4. Build for current platform to test
make build
./build/tcpscan --help

# 5. Build all platforms for release
make

# 6. Test the binary
./release/tcpscan-mac google.com -p 443
```

## Notes

- The `./release/` directory is created automatically on first build
- All binaries are stripped (`-s -w` ldflags) for smaller size
- Build paths are trimmed for reproducible builds
- Binaries are excluded from git via `.gitignore`
