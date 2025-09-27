# Build stage
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Set working directory
WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s" \
    -o oracle-cert-renew \
    .

# Runtime stage
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1000 -S appuser && \
    adduser -u 1000 -S appuser -G appuser

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/oracle-cert-renew /app/oracle-cert-renew

# Copy example configuration
COPY --from=builder /build/config.yaml.example /app/config.yaml.example

# Create directories for certificates and configs
RUN mkdir -p /app/certs /app/config && \
    chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/app/oracle-cert-renew", "-version"]

# Volume for configuration and certificates
VOLUME ["/app/config", "/app/certs"]

# Default command
ENTRYPOINT ["/app/oracle-cert-renew"]
CMD ["-config", "/app/config/config.yaml"]
