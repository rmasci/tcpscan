# Migration Guide: Original → Modernized TCPScan

## Quick Start

The modernized version is ready to use! Here's how to get started:

### Build the New Version

```bash
# Build all platform binaries (default)
make -f Makefile.new

# Or build for current platform only
make -f Makefile.new build

# Or directly with Go
go build -o tcpscan ./cmd/tcpscan

# All platform binaries will be in ./release/
# Current platform binary will be in ./build/tcpscan
```

### Test It Out

```bash
# Test the binary for your platform
./release/tcpscan-mac google.com -p 443        # macOS AMD64
./release/tcpscan-mac-arm google.com -p 443    # macOS ARM64
./release/tcpscan-l64 google.com -p 443        # Linux AMD64

# Or use the build directory for current platform
./build/tcpscan 127.0.0.1 -p 22
./build/tcpscan -C 192.168.1.0/24
```

## Side-by-Side Comparison

Both versions coexist in your repository:

| Aspect | Original | Modernized |
|--------|----------|------------|
| **Entry Point** | `tcpscan.go` (root) | `cmd/tcpscan/main.go` |
| **Build Command** | `make mac` (old Makefile) | `make` (Makefile.new) |
| **Binary Output** | `../tcpscan-release/` | `./release/` |
| **Go Version** | 1.17 | 1.21+ |
| **Structure** | Single package | Internal packages |
| **Git Tracking** | Binaries outside repo | `.gitignore` excludes binaries |

## What Changed (Developer View)

### 1. Package Structure

**Original:**
```
tcpscan/
├── tcpscan.go          (800 lines, everything)
├── format.go
├── tcpCheck.go
├── subnetcalc.go
└── digicert.go
```

**Modernized:**
```
tcpscan/
├── cmd/tcpscan/        (CLI entry point)
├── internal/
│   ├── types/          (Type definitions)
│   ├── scanner/        (Scan logic)
│   ├── parser/         (Target parsing)
│   ├── output/         (Formatting)
│   └── coordinator/    (Concurrency)
└── go.mod              (Go 1.21)
```

### 2. Configuration

**Original (Global Variables):**
```go
var verb bool
var debug bool
var sslCheck bool
// ... 10+ more globals
```

**Modernized (Config Struct):**
```go
config := &types.Config{
    Verbose:   true,
    Debug:     false,
    SSLCheck:  true,
    Timeout:   500 * time.Millisecond,
}
```

### 3. Concurrency

**Original:**
```go
results := make(chan string)
for i, scan := range scanAddr {
    go scanPort(scan, timeOut, i, showOpen, sslCheck, results)
}
```

**Modernized (errgroup):**
```go
g, ctx := errgroup.WithContext(ctx)
g.SetLimit(512)
for i := range targets {
    g.Go(func() error {
        return scanner.ScanTarget(ctx, targets[i])
    })
}
err := g.Wait()
```

### 4. Error Handling

**Original:**
```go
errorHandle(err, "Parse Duration Timeout", true)
```

**Modernized:**
```go
if err != nil {
    return fmt.Errorf("failed to parse timeout: %w", err)
}
```

## Switching to the Modernized Version

### Option 1: Gradual Migration (Recommended)

Keep both versions during transition:

```bash
# Build old version (still works)
make -f Makefile mac

# Build new version (all platforms)
make -f Makefile.new

# Test new version alongside old
./release/tcpscan-mac google.com -p 443
../tcpscan-release/tcpscan-mac google.com -p 443
```

### Option 2: Full Switch

Once you're confident:

```bash
# Backup old Makefile
mv Makefile Makefile.old

# Use new Makefile
mv Makefile.new Makefile

# Build all platforms (default)
make

# Or build just for current platform
make build

# Install
make install
```

## For CI/CD Pipelines

If you have automated builds:

**Old:**
```bash
make all  # Uses old Makefile, builds to ../tcpscan-release/
```

**New:**
```bash
make -f Makefile.new  # During transition, builds to ./release/
# or
make  # After switching (default target builds all platforms)
```

## Testing Checklist

Before fully migrating, test these scenarios:

- [ ] Basic scan: `./build/tcpscan 127.0.0.1 -p 22`
- [ ] Multiple ports: `./build/tcpscan google.com -p 80,443`
- [ ] Port range: `./build/tcpscan localhost -p 8000-8010`
- [ ] Subnet scan: `./build/tcpscan 192.168.1.0/29 -p 22`
- [ ] File input: `./build/tcpscan -f iplist.txt -p 443`
- [ ] SSL check: `./build/tcpscan google.com -p 443 -s`
- [ ] DNS lookup: `./build/tcpscan google.com -p 443 -d`
- [ ] ICMP ping: `./build/tcpscan google.com -p 443 -i`
- [ ] Show open only: `./build/tcpscan 192.168.1.0/29 -p 22 -o`
- [ ] CSV output: `./build/tcpscan google.com -p 443 -O csv`
- [ ] Excel output: `./build/tcpscan google.com -p 443 -e report.xlsx`
- [ ] Subnet calc: `./build/tcpscan -C 10.1.1.0/24`

## Rollback Plan

If you need to revert:

```bash
# The original code is untouched
# Just use the old Makefile
make -f Makefile.old mac

# Or build directly
go build -o tcpscan tcpscan.go digicert.go format.go \
    setFilesLinux.go tcpCheck.go subnetcalc.go
```

## Getting Help

Compare implementations:
- **Original scanning:** `tcpscan.go:482` (scanPort function)
- **Modernized scanning:** `internal/scanner/scanner.go:23` (ScanTarget method)

Both produce identical results!

## Next Steps

1. **Test the modernized version** with your typical use cases
2. **Run both versions side-by-side** to verify identical output
3. **Update your scripts** to use `./build/tcpscan` or install it
4. **Switch Makefile** when ready: `mv Makefile.new Makefile`
5. **Update documentation** to reference new structure

## Benefits You'll Get

- ✅ **Better error messages** with full context
- ✅ **Faster builds** with Go 1.21+
- ✅ **Easier to extend** with clean package structure
- ✅ **Better IDE support** with proper types
- ✅ **Context cancellation** (Ctrl+C works better)
- ✅ **Controlled concurrency** (no goroutine explosion)

## Questions?

The code is well-documented. Start here:
- `cmd/tcpscan/main.go` - Entry point
- `internal/types/types.go` - Core types
- `internal/scanner/scanner.go` - Scanning logic
- `MODERNIZATION.md` - Detailed changes

Both versions work identically from the user's perspective!
