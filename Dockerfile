# Multi-stage build for Amalthea
FROM rust:latest as builder

# Set working directory
WORKDIR /app

# Install dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy Cargo files first for better caching
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src/ ./src/

# Build the application
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy the binary from builder stage
COPY --from=builder /app/target/release/amalthea /usr/local/bin/amalthea

# Make binary executable
RUN chmod +x /usr/local/bin/amalthea

# Create non-root user
RUN groupadd -r amalthea && useradd -r -g amalthea amalthea
USER amalthea

# Set the binary as entrypoint
ENTRYPOINT ["amalthea"]

# Default command shows help
CMD ["--help"]