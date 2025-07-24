# Multi-stage Dockerfile for ArdaOS Compliance Compiler
# Optimized for security, size, and performance

# =============================================================================
# Build Stage
# =============================================================================
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    git \
    ca-certificates \
    tzdata \
    make

# Set working directory
WORKDIR /build

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build arguments for version information
ARG VERSION=dev
ARG BUILD_TIME
ARG GIT_COMMIT
ARG GIT_BRANCH

# Build the compliance compiler with optimizations
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -a -installsuffix cgo \
    -ldflags "-s -w -X main.version=${VERSION} -X main.buildTime=${BUILD_TIME} -X main.gitCommit=${GIT_COMMIT} -X main.gitBranch=${GIT_BRANCH}" \
    -o compliance-compiler \
    ./cmd/compliance-compiler

# Verify the binary
RUN ./compliance-compiler --version

# =============================================================================
# Runtime Stage
# =============================================================================
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    curl \
    && rm -rf /var/cache/apk/*

# Create non-root user for security
RUN addgroup -g 1001 -S ardaos && \
    adduser -u 1001 -S ardaos -G ardaos

# Set working directory
WORKDIR /app

# Copy timezone data
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copy CA certificates
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the compiled binary
COPY --from=builder /build/compliance-compiler /usr/local/bin/compliance-compiler

# Create directories for data and config
RUN mkdir -p /app/data /app/config /app/examples /app/output && \
    chown -R ardaos:ardaos /app

# Copy example policies and templates
COPY --chown=ardaos:ardaos examples/ /app/examples/

# Create health check script
RUN echo '#!/bin/sh' > /usr/local/bin/healthcheck && \
    echo 'compliance-compiler --version >/dev/null 2>&1' >> /usr/local/bin/healthcheck && \
    chmod +x /usr/local/bin/healthcheck

# Switch to non-root user
USER ardaos

# Set environment variables
ENV PATH="/usr/local/bin:${PATH}"
ENV TZ=UTC
ENV COMPLIANCE_COMPILER_DATA_DIR=/app/data
ENV COMPLIANCE_COMPILER_CONFIG_DIR=/app/config
ENV COMPLIANCE_COMPILER_OUTPUT_DIR=/app/output

# Expose volumes
VOLUME ["/app/data", "/app/config", "/app/output"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD /usr/local/bin/healthcheck

# Default command
ENTRYPOINT ["compliance-compiler"]
CMD ["--help"]

# =============================================================================
# Metadata
# =============================================================================
LABEL maintainer="Arda OS Team"
LABEL description="ArdaOS Compliance Compiler - Policy compilation and validation tool"
LABEL version="${VERSION}"
LABEL org.opencontainers.image.title="ArdaOS Compliance Compiler"
LABEL org.opencontainers.image.description="Policy compilation and validation tool for ArdaOS blockchain compliance engine"
LABEL org.opencontainers.image.version="${VERSION}"
LABEL org.opencontainers.image.source="https://github.com/ardaos/arda-os"
LABEL org.opencontainers.image.documentation="https://docs.ardaos.com/compliance-compiler"
LABEL org.opencontainers.image.licenses="Apache-2.0"
