.PHONY: help build test lint clean install

# Default target
help:
	@echo "Stash Client Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  build    - Build client binary"
	@echo "  install  - Install binary to GOPATH/bin"
	@echo "  test     - Run unit tests"
	@echo "  lint     - Run linters"
	@echo "  clean    - Clean build artifacts"
	@echo "  deps     - Download and tidy dependencies"

# Build binary
build:
	@echo "Building client binary..."
	@mkdir -p bin
	CGO_ENABLED=0 go build -o bin/stash ./cmd/stash

# Install binary
install: build
	@echo "Installing client binary..."
	go install ./cmd/stash

# Run tests
test:
	@echo "Running tests..."
	go test -v -race -coverprofile=coverage.out ./...

# Run linters
lint:
	@echo "Running linters..."
	golangci-lint run

# Clean build artifacts
clean:
	@echo "Cleaning..."
	rm -rf bin/
	rm -f coverage.out

# Download dependencies
deps:
	@echo "Downloading dependencies..."
	go mod download
	go mod tidy
