# === Build Stage ===
FROM golang:1.23-alpine AS builder

# Install make and git (needed for version info)
RUN apk add --no-cache make git ca-certificates tzdata

# Set working directory
WORKDIR /build

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy the entire project
COPY . .

# Build using Makefile to ensure consistent build patterns
RUN make build


# === Runtime Stage ===
FROM alpine:latest

# Install ca-certificates for HTTPS requests
RUN apk --no-cache add ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1000 checks && \
    adduser -D -u 1000 -G checks checks

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/bin/checks /app/checks

# Change ownership
RUN chown -R checks:checks /app

# Switch to non-root user
USER checks

# Expose default port (adjust if needed)
EXPOSE 8080

# Run the application
ENTRYPOINT ["/app/checks"]
