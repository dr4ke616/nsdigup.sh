# checks.sh

A `curl`-first domain health utility that aggregates Domain Identity, Certificate Health, and Configuration gaps into a high-density ANSI report.

## Features

- **DNS Analysis**: IP resolution, nameserver enumeration
- **Certificate Scanning**: SSL/TLS certificate details, expiry, wildcard detection
- **Security Configuration**: SPF/DMARC email security, HTTP security headers
- **Fast Response**: <2s response time with concurrent scanning
- **Standard Library Only**: No external dependencies

## Usage

Start the server:
```bash
go run cmd/checks/main.go
```

Query a domain:
```bash
curl http://localhost:8080/google.com | jq '.'
```

## Build

```bash
go build -o checks cmd/checks/main.go
./checks
```

## Test

Run all tests:
```bash
go test ./... -v
```

Run scanner tests specifically:
```bash
go test ./internal/scanner/ -v
```

## Architecture

- `cmd/checks/main.go` - Application entry point
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
  "misconfigurations": {
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
