# nsdigup.sh

A `curl`-first domain health utility that aggregates Domain Identity, Certificate Health, and Configuration gaps into a high-density ANSI report.

## Features

- **DNS Analysis**: IP resolution, nameserver enumeration
- **Certificate Scanning**: SSL/TLS certificate details, expiry, wildcard detection
- **Security Configuration**: SPF/DMARC email security, HTTP security headers
- **Fast Response**: <2s response time with concurrent scanning
- **Standard Library Only**: No external dependencies

## Quick Start

### Development
Start the server in dev mode:
```bash
make dev
```

### Production Build
Build and run:
```bash
make build
make run
```

Query a domain:
```bash
curl http://localhost:8080/google.com | jq '.'
```

Check version:
```bash
./bin/nsdigup.sh --version
```

## Build & Development

The project uses a Makefile for common development tasks:

### Building
```bash
make build              # Build binary to bin/checks
make build-all          # Build for multiple platforms
make install            # Install to $GOPATH/bin
make clean              # Remove build artifacts
```

### Testing
```bash
make test               # Run all tests
make test-verbose       # Run tests with verbose output
make test-coverage      # Generate coverage report
make test-coverage-html # Generate HTML coverage report
```

### Code Quality
```bash
make fmt                # Format all Go files
make vet                # Run go vet
make lint               # Run golangci-lint
make check              # Run fmt, vet, and test
```

### Running
```bash
make run                # Build and run
make dev                # Run without building (go run)
```

### Version Management
Version information is automatically injected during build from git:
```bash
make build
./bin/nsdigup.sh --version  # Shows version, commit, and build time
```

To create a versioned release:
```bash
git tag v1.0.0
make build
```

See all available commands:
```bash
make help
```

## Architecture

- `cmd/nsdigup/main.go` - Application entry point
- `internal/server/handler.go` - HTTP handlers
- `internal/scanner/` - Domain scanning modules
  - `orchestrator.go` - Coordinates concurrent scans
  - `dns.go` - DNS/IP resolution
  - `ssl.go` - Certificate analysis
  - `config.go` - Security configuration checks
- `pkg/models/report.go` - Shared data structures

## Example Output

```json
{
  "target": "google.com",
  "timestamp": "2025-12-23T11:38:03Z",
  "identity": {
    "ip_address": "74.125.193.100",
    "nameservers": ["ns1.google.com", "ns2.google.com"]
  },
  "certificates": {
    "current": {
      "issuer": "WR2",
      "common_name": "*.google.com",
      "expires_at": "2026-02-25T15:49:26Z",
      "status": "Active",
      "is_wildcard": true
    }
  },
  "findings": {
    "email_security": {
      "dmarc_policy": "reject",
      "spf_record": "v=spf1 include:_spf.google.com ~all"
    },
    "header_issues": [
      "Missing HSTS header",
      "Missing CSP header"
    ]
  }
}
```
