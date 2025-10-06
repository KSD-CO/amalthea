# Makefile for Amalthea

# Extract version from Cargo.toml
VERSION := $(shell grep '^version = ' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/')

.PHONY: all build linux clean help release version dev test check run docker docker-push publish-crate publish

# Default target
all: build

# Build for current platform
build:
	@echo "🚀 Building Amalthea..."
	cargo build --release
	@echo "✅ Build completed: target/release/amalthea"

# Build for Linux (cross-compile if needed)
linux:
	@echo "🚀 Building for Linux x86_64..."
	cargo build --release --target x86_64-unknown-linux-gnu
	@mkdir -p releases
	cp target/x86_64-unknown-linux-gnu/release/amalthea releases/amalthea-linux-x86_64
	@echo "✅ Linux build completed: releases/amalthea-linux-x86_64"

# Build Docker image
docker:
	@echo "🐳 Building Docker image..."
	@echo "📦 Version: $(VERSION)"
	sudo docker build -t ksdco/amalthea:$(VERSION) -t ksdco/amalthea:latest .
	@echo "✅ Docker image built successfully!"

# Push Docker image to Docker Hub  
docker-push: docker
	@echo "🚀 Pushing Docker image to Docker Hub..."
	@echo "📦 Version: $(VERSION)"
	sudo docker push ksdco/amalthea:$(VERSION)
	sudo docker push ksdco/amalthea:latest
	@echo "✅ Docker images pushed successfully!"
	@echo "📦 Available images:"
	@echo "   docker pull ksdco/amalthea:$(VERSION)"
	@echo "   docker pull ksdco/amalthea:latest"

# Publish to crates.io
publish-crate:
	@echo "📦 Publishing Amalthea v$(VERSION) to crates.io..."
	@echo "⚠️  Make sure you're logged in: cargo login"
	@echo "🔍 Running pre-publish checks..."
	cargo check
	cargo test
	@echo "🚀 Publishing to crates.io..."
	cargo publish
	@echo "✅ Published to crates.io successfully!"
	@echo "📦 Available at: https://crates.io/crates/amalthea"

# Complete publish: Linux build + Crates.io + Docker Hub
publish: clean
	@echo "🚀 Starting complete publication process..."
	@echo "📦 Version: $(VERSION)"
	@echo ""
	@echo "🔄 Step 1/3: Building for Linux..."
	@make linux
	@echo ""
	@echo "🔄 Step 2/3: Publishing to crates.io..."
	@make publish-crate
	@echo ""
	@echo "🔄 Step 3/3: Publishing Docker images..."
	@make docker-push
	@echo ""
	@echo "🎉 Complete publication finished!"
	@echo "📦 Linux binary: releases/amalthea-linux-x86_64"
	@echo "📦 Crates.io: https://crates.io/crates/amalthea"
	@echo "📦 Docker Hub: docker pull ksdco/amalthea:$(VERSION)"

# Clean build artifacts
clean:
	@echo "🧹 Cleaning build artifacts..."
	cargo clean
	rm -rf releases/
	@echo "✅ Clean completed"

# Create release build
release: clean build
	@echo "📦 Creating release build..."
	@echo "Current version: $(VERSION)"
	@echo "Binary: target/release/amalthea"

# Show available targets
help:
	@echo "Available targets:"
	@echo "  build       - Build for current platform"
	@echo "  linux       - Build for Linux x86_64"
	@echo "  docker      - Build Docker image"
	@echo "  docker-push - Build and push Docker image to Docker Hub"
	@echo "  publish-crate - Publish to crates.io"
	@echo "  publish     - Complete publish (Linux + Crates + Docker)"
	@echo "  clean       - Clean build artifacts"
	@echo "  release     - Create release build"
	@echo "  version     - Show current version"
	@echo "  dev         - Development build (debug)"
	@echo "  test        - Run tests"
	@echo "  check       - Check code without building"
	@echo "  run         - Build and run with sample API"
	@echo "  help        - Show this help"

# Show current version
version:
	@echo "📦 Amalthea version: $(VERSION)"

# Development targets
dev:
	@echo "🔧 Development build..."
	cargo build

test:
	@echo "🧪 Running tests..."
	cargo test

check:
	@echo "🔍 Checking code..."
	cargo check

# Quick run with test API
run: build
	@echo "🚀 Running Amalthea with local model..."
	@echo "💡 Make sure Ollama is running: ollama serve"
	./target/release/amalthea --provider local --model mistral:latest --file ~/Downloads/problem-solving.json --generate-only
