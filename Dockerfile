FROM alpine:latest

# Install ca-certificates for HTTPS requests
RUN apk --no-cache add ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1000 nsdigup && \
    adduser -D -u 1000 -G nsdigup nsdigup

# Set working directory
WORKDIR /app

# Copy pre-built binary from host
COPY bin/nsdigup.sh /app/nsdigup.sh

# Change ownership
RUN chown -R nsdigup:nsdigup /app

# Switch to non-root user
USER nsdigup

# Expose default port (adjust if needed)
EXPOSE 8080

# Run the application
ENTRYPOINT ["/app/nsdigup.sh"]
