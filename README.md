# nsdigup.sh

A comprehensive domain health monitoring HTTP service that provides instant security and configuration analysis for any domain. Built for curl-first interaction with high-density ANSI output and JSON support.

## What It Does

nsdigup.sh performs parallel security scans across multiple dimensions:

- **DNS & Identity**: IP resolution, nameserver enumeration, WHOIS data, DNSSEC validation, CAA records
- **SSL/TLS Security**: Certificate details, expiry tracking, wildcard detection, TLS version analysis, weak cipher identification
- **Email Security**: SPF and DMARC policy validation with weakness detection
- **HTTP Security**: Security header analysis (HSTS, CSP, X-Frame-Options, etc.), HTTPS redirect checking
- **Performance**: Concurrent scanning with <2s response time, optional in-memory caching

## Quick Start

### Start the Server

```bash
# Development mode
make dev

# Production build and run
make build
make run

# Or with custom configuration
./bin/nsdigup.sh --port 3000 --cache-ttl 10m
```

### Query a Domain

```bash
# ANSI output (default, human-readable)
curl http://localhost:8080/google.com

# JSON output (for automation)
curl -H "Accept: application/json" http://localhost:8080/google.com

# With jq for pretty JSON
curl -H "Accept: application/json" http://localhost:8080/github.com | jq .
```

### Check Server Health

```bash
curl http://localhost:8080/health
```

## Configuration

### Environment Variables

```bash
export NSDIGUP_PORT=8080
export NSDIGUP_HOST=0.0.0.0
export NSDIGUP_ADVERTISED_ADDRESS=https://nsdigup.sh
export NSDIGUP_CACHE_MODE=mem          # 'mem' or 'none'
export NSDIGUP_CACHE_TTL=5m            # Duration: 30s, 5m, 1h, etc.
export NSDIGUP_LOG_LEVEL=info          # debug, info, warn, error
export NSDIGUP_LOG_FORMAT=text         # text or json
```

### Command Line Flags

```bash
./bin/nsdigup.sh \
  --port 8080 \
  --host 0.0.0.0 \
  --name https://nsdigup.sh \
  --cache-mode mem \
  --cache-ttl 10m \
  --log-level info \
  --log-format text
```

Command line flags override environment variables.

## Features in Detail

### DNS & Domain Identity

- **IP Resolution**: Primary IPv4 address lookup
- **Nameservers**: Complete NS record enumeration
- **WHOIS Data**: Registrar information and domain ownership
- **DNSSEC**: Validation status and error reporting
- **CAA Records**: Certificate Authority Authorization policy

### SSL/TLS Analysis

- **Certificate Chain**: Issuer, common name, expiration dates
- **Wildcard Detection**: Identifies wildcard certificates
- **Status Tracking**: Active, expired, or expiring soon
- **TLS Protocol Versions**: Supported TLS versions (1.0, 1.1, 1.2, 1.3)
- **Weak Protocol Detection**: Flags deprecated TLS 1.0/1.1
- **Cipher Suites**: Lists all supported ciphers
- **Weak Cipher Detection**: Identifies insecure cipher configurations

### Email Security

- **SPF Records**: Sender Policy Framework validation
- **DMARC Policy**: Domain-based Message Authentication, Reporting, and Conformance
- **Weakness Analysis**: Detects permissive policies (softfail, none, quarantine)

### HTTP Security Headers

Analyzes presence and strength of:
- **HSTS** (HTTP Strict Transport Security)
- **CSP** (Content Security Policy) - detects unsafe-inline/unsafe-eval
- **X-Frame-Options** - clickjacking protection
- **X-Content-Type-Options** - MIME sniffing prevention
- **Referrer-Policy** - referrer information control
- **Permissions-Policy** - feature access control

### HTTPS Redirect Checking

- **Redirect Detection**: Tests if HTTP redirects to HTTPS
- **Status Codes**: Captures redirect response codes
- **Loop Detection**: Identifies redirect loops
- **Final URL**: Tracks complete redirect chain

## Output Formats

### ANSI (Default)

High-density terminal output optimized for curl:

```
═══ nsdigup.sh ═══
Target: google.com
Scanned: 2025-12-26T18:30:00Z

[ IDENTITY ]
IP: 142.250.185.46
Nameservers: ns1.google.com, ns2.google.com, ns3.google.com, ns4.google.com
DNSSEC: Enabled ✓
CAA: google.com, pki.goog, globalsign.com

[ CERTIFICATES ]
Issuer: WR2
Common Name: *.google.com (wildcard)
Expires: 2026-02-25T15:49:26Z (Active)
TLS Versions: TLS 1.2, TLS 1.3

[ SECURITY FINDINGS ]
Email Security:
  SPF: v=spf1 include:_spf.google.com ~all
  DMARC: reject

HTTP Security Headers:
  ⚠ Missing HSTS header
  ⚠ Missing CSP header
```

### JSON

Structured data for automation and integration:

```json
{
  "target": "google.com",
  "timestamp": "2025-12-26T18:30:00Z",
  "identity": {
    "ip_address": "142.250.185.46",
    "nameservers": ["ns1.google.com", "ns2.google.com"],
    "dnssec_enabled": true,
    "dnssec_valid": true,
    "caa_records": ["google.com", "pki.goog"],
    "registrar": "MarkMonitor Inc."
  },
  "certificates": {
    "issuer": "WR2",
    "common_name": "*.google.com",
    "expires_at": "2026-02-25T15:49:26Z",
    "status": "Active",
    "is_wildcard": true,
    "tls_versions": ["TLS 1.2", "TLS 1.3"],
    "weak_tls_versions": []
  },
  "findings": {
    "email_security": {
      "spf_record": "v=spf1 include:_spf.google.com ~all",
      "dmarc_policy": "reject",
      "is_weak": false
    },
    "header_issues": [
      "Missing HSTS header",
      "Missing CSP header"
    ],
    "https_redirect": {
      "enabled": true,
      "status_code": 301,
      "final_url": "https://google.com/"
    }
  }
}
```

## Caching

nsdigup.sh includes an intelligent caching layer to reduce redundant DNS lookups and API calls:

- **In-Memory Cache**: Fast, zero-dependency caching (default)
- **No-Op Cache**: Disable caching for development or always-fresh results
- **TTL-Based Expiration**: Configurable time-to-live (default: 5 minutes)
- **Automatic Cleanup**: Background goroutine removes expired entries
- **Cache Hit Logging**: Track cache effectiveness in debug logs

```bash
# Enable caching with 10-minute TTL
./bin/nsdigup.sh --cache-mode mem --cache-ttl 10m

# Disable caching
./bin/nsdigup.sh --cache-mode none
```

## API Endpoints

### `GET /{domain}`

Scan a domain and return results.

**Request:**
```bash
curl http://localhost:8080/example.com
curl -H "Accept: application/json" http://localhost:8080/example.com
```

**Response:**
- `200 OK` - Scan completed (ANSI or JSON based on Accept header)
- `400 Bad Request` - Invalid domain format
- `500 Internal Server Error` - Scan failure

### `GET /health`

Health check endpoint for load balancers and monitoring.

**Request:**
```bash
curl http://localhost:8080/health
```

**Response:**
- `200 OK` - Service is healthy
- `{ "status": "ok" }`

### `GET /`

Landing page with usage instructions.

**Request:**
```bash
curl http://localhost:8080/
```

**Response:**
- ASCII banner with feature list and examples

## Architecture

```
nsdigup/
├── cmd/nsdigup/                  # Application entry point
│   └── main.go                   # Server initialization and startup
│
├── internal/
│   ├── banner/                   # ASCII art and branding
│   │   └── ascii.go
│   │
│   ├── cache/                    # Caching layer
│   │   ├── store.go              # Cache interface
│   │   ├── memory.go             # In-memory implementation
│   │   └── noop.go               # No-op implementation
│   │
│   ├── config/                   # Configuration management
│   │   └── config.go             # Env vars and flags
│   │
│   ├── logger/                   # Structured logging
│   │   └── logger.go             # slog wrapper
│   │
│   ├── renderer/                 # Output formatting
│   │   ├── ansi.go               # Terminal output
│   │   └── json.go               # JSON serialization
│   │
│   ├── scanner/                  # Core scanning logic
│   │   ├── scanner.go            # Parallel scan orchestration
│   │   ├── identity.go           # DNS, WHOIS, DNSSEC, CAA
│   │   ├── certificates.go       # TLS/SSL analysis
│   │   ├── findings.go           # Security configuration checks
│   │   └── tools/                # Low-level utilities
│   │       ├── dns.go            # DNS lookups
│   │       ├── certs.go          # Certificate parsing
│   │       ├── tls_analyzer.go   # TLS protocol/cipher analysis
│   │       ├── security.go       # HTTP security headers
│   │       ├── whois.go          # WHOIS queries
│   │       ├── dnssec.go         # DNSSEC validation
│   │       ├── caa.go            # CAA record checks
│   │       └── redirect.go       # HTTPS redirect testing
│   │
│   └── server/                   # HTTP server
│       ├── handler.go            # Request routing
│       ├── domain_handler.go     # Domain scan endpoint
│       ├── health_handler.go     # Health check endpoint
│       ├── root_handler.go       # Landing page
│       └── middleware.go         # Logging middleware
│
└── pkg/models/                   # Shared data structures
    └── report.go                 # Report, Identity, Certificates, Findings
```

### Design Principles

1. **Concurrent Execution**: All scanners run in parallel using goroutines
2. **Graceful Degradation**: Partial results returned even if some scanners fail
3. **Timeout Management**: Each scanner has configurable timeouts
4. **Structured Logging**: All operations logged with context using slog
5. **Zero External Dependencies**: Only Go standard library (except DNS/WHOIS)
6. **HTTP-First**: Designed for curl and programmatic access

## Build & Development

### Prerequisites

- Go 1.21 or later
- Make (optional, for convenience commands)
- Git (for version injection)

### Building

```bash
# Standard build
make build

# Build for multiple platforms
make build-all

# Install to $GOPATH/bin
make install

# Clean build artifacts
make clean
```

Binary will be created at `bin/nsdigup.sh` with version info automatically injected from git.

### Testing

```bash
# Run all tests
make test

# Verbose test output
make test-verbose

# Generate coverage report
make test-coverage

# HTML coverage report
make test-coverage-html
```

### Code Quality

```bash
# Format code
make fmt

# Run go vet
make vet

# Run all quality checks
make check
```

### Running

```bash
# Build and run
make run

# Run without building (development)
make dev

# Run with custom config
./bin/nsdigup.sh --port 3000 --cache-mode none --log-level debug
```

### Docker

```bash
# Build Docker image
docker build -t nsdigup.sh .

# Run container
docker run -p 8080:8080 nsdigup.sh

# With custom config
docker run -p 3000:3000 -e NSDIGUP_PORT=3000 -e NSDIGUP_CACHE_TTL=10m nsdigup.sh
```

## Version Management

Version information (version, git commit, build time) is automatically injected during build and displayed in startup logs:

```
time=2025-12-26T18:30:00Z level=INFO msg="application starting"
  version=v1.0.0 commit=a1b2c3d build_time=2025-12-26T18:30:00Z
```

To create a versioned release:

```bash
git tag v1.0.0
make build
```

## Performance

- **Response Time**: <2 seconds for most domains
- **Concurrent Scanning**: 3 parallel scan types (identity, certificates, findings)
- **Caching**: Optional in-memory cache with configurable TTL
- **Timeouts**: 10-second default per scanner, customizable
- **Lightweight**: Single binary, ~10MB, minimal memory footprint

## Troubleshooting

### Enable Debug Logging

```bash
./bin/nsdigup.sh --log-level debug
```

This will show:
- Detailed scan progress
- Cache hits and misses
- Individual scanner timings
- Partial failure details

### Common Issues

**"Scan failed" errors**: Some domains have strict firewall rules. Check logs for specific scanner failures.

**Slow responses**: Increase timeouts or check network connectivity. WHOIS lookups can be slow for some TLDs.

**Cache not working**: Verify `--cache-mode mem` is set and TTL is greater than 0.

**DNS resolution fails**: Ensure the server can reach public DNS servers. Test with `dig` or `nslookup`.

## License

MIT License - See LICENSE file for details

## Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure `make check` passes
5. Submit a pull request
