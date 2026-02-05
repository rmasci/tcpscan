.PHONY: all build clean test lint deps help release
.PHONY: linux64 linuxa64 mac mac-arm win64 pi openbsd64 netbsd64 freebsd64 solaris
.PHONY: install

BINARY_NAME=tcpscan
CMD_PATH=./cmd/tcpscan
BUILD_DIR=./build
RELEASE_DIR=./release

# Version information
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
GIT_COMMIT=$(shell git rev-parse HEAD 2>/dev/null || echo "unknown")
BUILD_DATE=$(shell date -u '+%Y-%m-%d_%H:%M:%S')

LDFLAGS=-s -w \
	-X 'main.version=$(VERSION)' \
	-X 'main.gitCommit=$(GIT_COMMIT)' \
	-X 'main.buildDate=$(BUILD_DATE)'
GCFLAGS=-trimpath=$(shell pwd)
ASMFLAGS=-trimpath=$(shell pwd)

# Default target - build all binaries
all: mac mac-arm pi linux64 linuxa64 netbsd64 openbsd64 freebsd64 win64 solaris
	@echo ""
	@echo "✓ All binaries built successfully in $(RELEASE_DIR)/"
	@echo ""

help:
	@echo "Available targets:"
	@echo "  make            - Build all platform binaries (default)"
	@echo "  make build      - Build for current platform only"
	@echo "  make test       - Run tests"
	@echo "  make lint       - Run linter"
	@echo "  make deps       - Update dependencies"
	@echo "  make clean      - Remove build artifacts"
	@echo "  make install    - Install binary to GOPATH/bin"
	@echo "  make release    - Increment version tag, push, and build all platforms"
	@echo ""
	@echo "Platform-specific targets:"
	@echo "  make mac        - macOS AMD64"
	@echo "  make mac-arm    - macOS ARM64 (Apple Silicon)"
	@echo "  make linux64    - Linux AMD64"
	@echo "  make linuxa64   - Linux ARM64"
	@echo "  make win64      - Windows AMD64"
	@echo "  make pi         - Raspberry Pi"
	@echo "  make openbsd64  - OpenBSD AMD64"
	@echo "  make netbsd64   - NetBSD AMD64"
	@echo "  make freebsd64  - FreeBSD AMD64"
	@echo "  make solaris    - Solaris AMD64"

release:
	@echo "Creating new release..."
	@# Get current version
	@CURRENT_VERSION=$$(git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//'); \
	if [ -z "$$CURRENT_VERSION" ]; then \
		echo "No existing tags found. Creating v1.0.0"; \
		NEW_VERSION="1.0.0"; \
	else \
		echo "Current version: v$$CURRENT_VERSION"; \
		MAJOR=$$(echo $$CURRENT_VERSION | cut -d. -f1); \
		MINOR=$$(echo $$CURRENT_VERSION | cut -d. -f2); \
		PATCH=$$(echo $$CURRENT_VERSION | cut -d. -f3); \
		PATCH=$$((PATCH + 1)); \
		NEW_VERSION="$$MAJOR.$$MINOR.$$PATCH"; \
	fi; \
	echo "New version: v$$NEW_VERSION"; \
	echo ""; \
	read -p "Create and push tag v$$NEW_VERSION? [y/N] " -n 1 -r; \
	echo ""; \
	if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		git tag -a "v$$NEW_VERSION" -m "Release v$$NEW_VERSION"; \
		git push origin "v$$NEW_VERSION"; \
		echo ""; \
		echo "Tag v$$NEW_VERSION created and pushed"; \
		echo "Building all platform binaries with version v$$NEW_VERSION..."; \
		echo ""; \
		$(MAKE) all; \
	else \
		echo "Release cancelled"; \
		exit 1; \
	fi

build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	go build -ldflags="$(LDFLAGS)" -gcflags="$(GCFLAGS)" -asmflags="$(ASMFLAGS)" \
		-o $(BUILD_DIR)/$(BINARY_NAME) $(CMD_PATH)

install: build
	@echo "Installing $(BINARY_NAME)..."
	go install $(CMD_PATH)

linux64:
	@echo "Building for Linux AMD64..."
	@mkdir -p $(RELEASE_DIR)
	GOOS=linux GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -gcflags="$(GCFLAGS)" -asmflags="$(ASMFLAGS)" \
		-o $(RELEASE_DIR)/$(BINARY_NAME)-l64 $(CMD_PATH)

linuxa64:
	@echo "Building for Linux ARM64..."
	@mkdir -p $(RELEASE_DIR)
	GOOS=linux GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -gcflags="$(GCFLAGS)" -asmflags="$(ASMFLAGS)" \
		-o $(RELEASE_DIR)/$(BINARY_NAME)-la64 $(CMD_PATH)

mac:
	@echo "Building for macOS AMD64..."
	@mkdir -p $(RELEASE_DIR)
	GOOS=darwin GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -gcflags="$(GCFLAGS)" -asmflags="$(ASMFLAGS)" \
		-o $(RELEASE_DIR)/$(BINARY_NAME)-mac $(CMD_PATH)

mac-arm:
	@echo "Building for macOS ARM64 (Apple Silicon)..."
	@mkdir -p $(RELEASE_DIR)
	GOOS=darwin GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -gcflags="$(GCFLAGS)" -asmflags="$(ASMFLAGS)" \
		-o $(RELEASE_DIR)/$(BINARY_NAME)-mac-arm $(CMD_PATH)

win64:
	@echo "Building for Windows AMD64..."
	@mkdir -p $(RELEASE_DIR)
	GOOS=windows GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -gcflags="$(GCFLAGS)" -asmflags="$(ASMFLAGS)" \
		-o $(RELEASE_DIR)/$(BINARY_NAME)-w64.exe $(CMD_PATH)

pi:
	@echo "Building for Raspberry Pi..."
	@mkdir -p $(RELEASE_DIR)
	GOOS=linux GOARCH=arm GOARM=6 go build -ldflags="$(LDFLAGS)" -gcflags="$(GCFLAGS)" -asmflags="$(ASMFLAGS)" \
		-o $(RELEASE_DIR)/$(BINARY_NAME)-pi $(CMD_PATH)

openbsd64:
	@echo "Building for OpenBSD AMD64..."
	@mkdir -p $(RELEASE_DIR)
	GOOS=openbsd GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -gcflags="$(GCFLAGS)" -asmflags="$(ASMFLAGS)" \
		-o $(RELEASE_DIR)/$(BINARY_NAME)-ob64 $(CMD_PATH)

netbsd64:
	@echo "Building for NetBSD AMD64..."
	@mkdir -p $(RELEASE_DIR)
	GOOS=netbsd GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -gcflags="$(GCFLAGS)" -asmflags="$(ASMFLAGS)" \
		-o $(RELEASE_DIR)/$(BINARY_NAME)-net64 $(CMD_PATH)

freebsd64:
	@echo "Building for FreeBSD AMD64..."
	@mkdir -p $(RELEASE_DIR)
	GOOS=freebsd GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -gcflags="$(GCFLAGS)" -asmflags="$(ASMFLAGS)" \
		-o $(RELEASE_DIR)/$(BINARY_NAME)-free64 $(CMD_PATH)

solaris:
	@echo "Building for Solaris AMD64..."
	@mkdir -p $(RELEASE_DIR)
	GOOS=solaris GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -gcflags="$(GCFLAGS)" -asmflags="$(ASMFLAGS)" \
		-o $(RELEASE_DIR)/$(BINARY_NAME)-sol $(CMD_PATH)

deps:
	@echo "Updating dependencies..."
	jf go mod tidy
	jf go mod verify

test:
	@echo "Running tests..."
	go test -v -race -coverprofile=coverage.out ./...

lint:
	@echo "Running linter..."
	@which golangci-lint > /dev/null || (echo "golangci-lint not found, install it from https://golangci-lint.run/usage/install/" && exit 1)
	golangci-lint run ./...

clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	rm -rf $(RELEASE_DIR)
	rm -f coverage.out
	@echo "Done."
