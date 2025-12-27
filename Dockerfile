# === Build Stage ===
FROM golang:1.25.5-alpine AS builder

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
RUN addgroup -g 1000 nsdigup && \
    adduser -D -u 1000 -G nsdigup nsdigup

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/bin/nsdigup.sh /app/nsdigup.sh

# Change ownership
RUN chown -R nsdigup:nsdigup /app

# Switch to non-root user
USER nsdigup

# Expose default port (adjust if needed)
EXPOSE 8080

# Run the application
ENTRYPOINT ["/app/nsdigup.sh"]
