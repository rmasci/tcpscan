# TCPScan Technical Documentation

This directory contains the main application code and technical documentation for developers and maintainers.

## Documentation Index

### For Developers

- **[BUILD.md](BUILD.md)** - Build instructions, Makefile targets, and compilation details
- **[MODERNIZATION.md](MODERNIZATION.md)** - Technical details of the Go 1.21+ modernization
- **[MIGRATION_GUIDE.md](MIGRATION_GUIDE.md)** - Guide for migrating from the original codebase
- **[OPTIMIZATIONS.md](OPTIMIZATIONS.md)** - Performance optimizations and benchmarking
- **[CHANGELOG.md](CHANGELOG.md)** - Version history and changes

### Quick Reference

#### Building

```bash
# Build for current platform
make build

# Build for all platforms
make

# Build with version info
make build  # Automatically includes git tag version
```

#### Project Structure

```
cmd/tcpscan/
├── main.go              # Application entry point
├── helpers.go           # Subnet calculator, SSL certs
├── setfiles_unix.go     # Unix file limit handling
├── setfiles_windows.go  # Windows stub
└── [technical docs]     # This directory

internal/
├── types/               # Core type definitions
├── scanner/             # TCP/SSL/ICMP scanning logic
├── parser/              # Target and port parsing
├── output/              # Output formatting
└── coordinator/         # Concurrent scan management
```

#### Version Information

Version is automatically injected at build time from git tags:

```go
var (
    version   = "dev"      // From git describe --tags
    gitCommit = "unknown"  // From git rev-parse HEAD
    buildDate = "unknown"  // Build timestamp
)
```

#### Key Design Principles

1. **Validation Tool** - Not for discovery or exploitation
2. **2048 Scan Limit** - Safety feature to prevent misuse
3. **Memory Efficient** - Optimized allocations and reuse
4. **Fast Execution** - Concurrent scanning with controlled limits
5. **User Friendly** - Simple CLI, clear output

## Development Workflow

### Making Changes

1. Update code in appropriate package
2. Run tests: `go test ./...`
3. Build: `make build`
4. Test functionality
5. Update CHANGELOG.md
6. Commit and tag if releasing

### Adding Features

- **New scan types**: Extend `internal/scanner/`
- **Output formats**: Extend `internal/output/`
- **Input parsing**: Extend `internal/parser/`
- **Configuration**: Update `internal/types/`

### Performance Testing

```bash
# Run benchmarks
go test -bench=. -benchmem ./internal/scanner/
go test -bench=. -benchmem ./internal/output/

# Profile memory
go test -memprofile=mem.prof -bench=. ./internal/scanner/
go tool pprof mem.prof

# Profile CPU
go test -cpuprofile=cpu.prof -bench=. ./internal/scanner/
go tool pprof cpu.prof
```

## Code Style

Follow the project's Go coding style guidelines:
- Keep functions small and focused
- Use descriptive naming
- Document all exported symbols with GoDoc
- Add inline comments for complex logic
- Update README.md, CHANGELOG.md, and GoDoc with every change

## Release Process

1. Update CHANGELOG.md with changes
2. Commit all changes
3. Create and push git tag:
   ```bash
   git tag -a v2.0.0 -m "Release v2.0.0"
   git push origin v2.0.0
   ```
4. Build release binaries:
   ```bash
   make clean
   make
   ```
5. Binaries in `./release/` are ready for distribution

## Testing

```bash
# Run all tests
go test ./...

# Run with race detector
go test -race ./...

# Run with coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

## Dependencies

Update dependencies using the `jf` wrapper:

```bash
make deps
# or
jf go mod tidy
jf go mod verify
```

## Getting Help

- **User Documentation**: See [root README.md](../../README.md)
- **Build Issues**: See [BUILD.md](BUILD.md)
- **Performance**: See [OPTIMIZATIONS.md](OPTIMIZATIONS.md)
- **Migration**: See [MIGRATION_GUIDE.md](MIGRATION_GUIDE.md)
