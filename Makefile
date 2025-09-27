# Oracle SBC Certificate Renewal Tool Makefile

# Variables
BINARY_NAME=oracle-cert-renew
BINARY_DIR=bin
GO=go
GOFLAGS=-v
LDFLAGS=-ldflags "-s -w"
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(shell date +%Y%m%d-%H%M%S)
COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Build variables for versioning
LDFLAGS_VERSION=-ldflags "-s -w -X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME) -X main.Commit=$(COMMIT)"

# Platforms for cross-compilation
PLATFORMS=darwin linux windows
ARCHITECTURES=amd64 arm64

# Default target
.PHONY: all
all: build

# Build the binary
.PHONY: build
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BINARY_DIR)
	$(GO) build $(GOFLAGS) $(LDFLAGS_VERSION) -o $(BINARY_DIR)/$(BINARY_NAME) .
	@echo "Binary built: $(BINARY_DIR)/$(BINARY_NAME)"

# Run the application
.PHONY: run
run: build
	./$(BINARY_DIR)/$(BINARY_NAME) -config config.yaml

# Install the binary to $GOPATH/bin
.PHONY: install
install:
	@echo "Installing $(BINARY_NAME)..."
	$(GO) install $(LDFLAGS_VERSION) .
	@echo "$(BINARY_NAME) installed to $$GOPATH/bin"

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning..."
	@rm -rf $(BINARY_DIR)
	@rm -f $(BINARY_NAME)
	@$(GO) clean
	@echo "Clean complete"

# Run tests
.PHONY: test
test:
	@echo "Running tests..."
	$(GO) test -v -race -cover ./...

# Run tests with coverage report
.PHONY: test-coverage
test-coverage:
	@echo "Running tests with coverage..."
	$(GO) test -v -race -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Run benchmarks
.PHONY: bench
bench:
	@echo "Running benchmarks..."
	$(GO) test -bench=. -benchmem ./...

# Format code
.PHONY: fmt
fmt:
	@echo "Formatting code..."
	$(GO) fmt ./...
	@echo "Code formatting complete"

# Run go vet
.PHONY: vet
vet:
	@echo "Running go vet..."
	$(GO) vet ./...
	@echo "Vet complete"

# Run golint (requires: go install golang.org/x/lint/golint@latest)
.PHONY: lint
lint:
	@echo "Running golint..."
	@which golint > /dev/null || (echo "golint not found. Install with: go install golang.org/x/lint/golint@latest" && exit 1)
	golint ./...

# Run staticcheck (requires: go install honnef.co/go/tools/cmd/staticcheck@latest)
.PHONY: staticcheck
staticcheck:
	@echo "Running staticcheck..."
	@which staticcheck > /dev/null || (echo "staticcheck not found. Install with: go install honnef.co/go/tools/cmd/staticcheck@latest" && exit 1)
	staticcheck ./...

# Run all checks
.PHONY: check
check: fmt vet test
	@echo "All checks passed!"

# Download dependencies
.PHONY: deps
deps:
	@echo "Downloading dependencies..."
	$(GO) mod download
	$(GO) mod tidy
	@echo "Dependencies downloaded"

# Update dependencies
.PHONY: deps-update
deps-update:
	@echo "Updating dependencies..."
	$(GO) get -u ./...
	$(GO) mod tidy
	@echo "Dependencies updated"

# Build for multiple platforms
.PHONY: build-all
build-all:
	@echo "Building for all platforms..."
	@mkdir -p $(BINARY_DIR)
	@$(foreach GOOS, $(PLATFORMS),\
		$(foreach GOARCH, $(ARCHITECTURES),\
			$(shell export GOOS=$(GOOS); export GOARCH=$(GOARCH); \
				$(GO) build $(LDFLAGS_VERSION) -o $(BINARY_DIR)/$(BINARY_NAME)-$(GOOS)-$(GOARCH)$(if $(findstring windows,$(GOOS)),.exe,) . && \
				echo "Built: $(BINARY_NAME)-$(GOOS)-$(GOARCH)$(if $(findstring windows,$(GOOS)),.exe,)")))
	@echo "Multi-platform build complete"

# Build for Linux only (common for server deployments)
.PHONY: build-linux
build-linux:
	@echo "Building for Linux..."
	@mkdir -p $(BINARY_DIR)
	GOOS=linux GOARCH=amd64 $(GO) build $(LDFLAGS_VERSION) -o $(BINARY_DIR)/$(BINARY_NAME)-linux-amd64 .
	GOOS=linux GOARCH=arm64 $(GO) build $(LDFLAGS_VERSION) -o $(BINARY_DIR)/$(BINARY_NAME)-linux-arm64 .
	@echo "Linux build complete"

# Create release archives
.PHONY: release
release: clean build-all
	@echo "Creating release archives..."
	@mkdir -p releases
	@$(foreach GOOS, $(PLATFORMS),\
		$(foreach GOARCH, $(ARCHITECTURES),\
			$(shell cd $(BINARY_DIR) && \
				tar czf ../releases/$(BINARY_NAME)-$(VERSION)-$(GOOS)-$(GOARCH).tar.gz \
					$(BINARY_NAME)-$(GOOS)-$(GOARCH)$(if $(findstring windows,$(GOOS)),.exe,) && \
				echo "Created: releases/$(BINARY_NAME)-$(VERSION)-$(GOOS)-$(GOARCH).tar.gz")))
	@echo "Release archives created in ./releases/"

# Docker build (requires Dockerfile)
.PHONY: docker-build
docker-build:
	@echo "Building Docker image..."
	docker build -t $(BINARY_NAME):$(VERSION) .
	docker tag $(BINARY_NAME):$(VERSION) $(BINARY_NAME):latest
	@echo "Docker image built: $(BINARY_NAME):$(VERSION)"

# Generate sample configuration
.PHONY: config
config:
	@if [ ! -f config.yaml ]; then \
		cp config.yaml.example config.yaml; \
		echo "Created config.yaml from example"; \
	else \
		echo "config.yaml already exists"; \
	fi

# Development mode with auto-reload (requires: go install github.com/cosmtrek/air@latest)
.PHONY: dev
dev:
	@which air > /dev/null || (echo "air not found. Install with: go install github.com/cosmtrek/air@latest" && exit 1)
	air

# Initialize project (for new clones)
.PHONY: init
init: deps config
	@echo "Project initialized. Edit config.yaml with your SBC details."

# Show help
.PHONY: help
help:
	@echo "Oracle SBC Certificate Renewal Tool - Makefile"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  all            - Build the binary (default)"
	@echo "  build          - Build the binary for current platform"
	@echo "  build-all      - Build for all platforms"
	@echo "  build-linux    - Build for Linux (amd64 and arm64)"
	@echo "  run            - Build and run the application"
	@echo "  install        - Install the binary to \$$GOPATH/bin"
	@echo "  clean          - Remove build artifacts"
	@echo "  test           - Run tests"
	@echo "  test-coverage  - Run tests with coverage report"
	@echo "  bench          - Run benchmarks"
	@echo "  fmt            - Format code"
	@echo "  vet            - Run go vet"
	@echo "  lint           - Run golint"
	@echo "  staticcheck    - Run staticcheck"
	@echo "  check          - Run fmt, vet, and tests"
	@echo "  deps           - Download dependencies"
	@echo "  deps-update    - Update dependencies"
	@echo "  release        - Create release archives"
	@echo "  docker-build   - Build Docker image"
	@echo "  config         - Generate config.yaml from example"
	@echo "  dev            - Run in development mode with auto-reload"
	@echo "  init           - Initialize project for development"
	@echo "  help           - Show this help message"
	@echo ""
	@echo "Examples:"
	@echo "  make                    # Build the binary"
	@echo "  make test              # Run tests"
	@echo "  make build-linux       # Build for Linux"
	@echo "  make release           # Create release archives"

# Set default goal
.DEFAULT_GOAL := all
