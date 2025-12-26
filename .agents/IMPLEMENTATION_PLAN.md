# Implementation Plan: High-Priority Security Checks

## Executive Summary

Adding 5 high-priority security checks to checks.sh:
1. **DNSSEC Validation** - DNS security verification
2. **CAA Records** - Certificate authority authorization
3. **Complete WHOIS** - Domain registration information
4. **TLS Protocol/Cipher Analysis** - Detect weak TLS configurations
5. **HTTP→HTTPS Redirect** - Verify proper HTTPS enforcement

**Timeline:** 3-4 weeks | **Breaking Changes:** None | **Dependencies:** 2 new libraries

---

## Current Implementation Summary

The `checks.sh` application currently implements **three parallel scanners**:

### 1. Identity Scanner (`internal/scanner/identity.go`)
- ✅ DNS A/AAAA record lookup (IP resolution)
- ✅ NS record lookup (nameservers)
- ⚠️ WHOIS fields defined but NOT populated (Registrar, Owner, ExpiresDays)

### 2. Certificate Scanner (`internal/scanner/certificates.go`)
- ✅ TLS certificate retrieval (port 443)
- ✅ Issuer identification
- ✅ Expiration date tracking
- ✅ Wildcard certificate detection
- ✅ Status classification (Active/Expiring Soon/Expired)
- ⚠️ Certificate history tracking (defined but not implemented)

### 3. Misconfiguration Scanner (`internal/scanner/misconfigurations.go`)
- ✅ SPF record validation with weakness detection
- ✅ DMARC policy analysis with weakness detection
- ✅ HTTP security headers (6 headers):
  - HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- ✅ CSP weakness detection (unsafe-inline, unsafe-eval)
- ⚠️ DNS glue records (defined but not implemented)
- ⚠️ HTTP status code (HTTPDetails model exists but unused)

---

## Missing Fundamental Checks

### **High Priority - Core Security**

1. **DNSSEC Validation**
   - Verify DNSSEC signatures for DNS records
   - Critical for preventing DNS spoofing attacks

2. **CAA Records (Certificate Authority Authorization)**
   - Check which CAs are authorized to issue certificates
   - Important for preventing unauthorized certificate issuance

3. **HTTP to HTTPS Redirect**
   - Verify HTTP properly redirects to HTTPS
   - Test for proper redirect configuration

4. **TLS Protocol & Cipher Suite Analysis**
   - Check for deprecated protocols (SSLv3, TLS 1.0/1.1)
   - Verify strong cipher suites are used
   - Detect weak/insecure cipher configurations

5. **Complete WHOIS Implementation**
   - Populate Registrar, Owner, ExpiresDays fields
   - Currently defined in model but not fetched

### **Medium Priority - Email Security**

6. **MX Record Validation**
   - Check mail server configuration
   - Verify MX records point to valid servers

7. **DKIM Record Discovery**
   - Look for DomainKeys Identified Mail records
   - Complements existing SPF/DMARC checks

8. **MTA-STS & TLS-RPT**
   - Mail Transfer Agent Strict Transport Security
   - TLS reporting for mail servers

### **Medium Priority - Additional DNS/Network**

9. **MX Record Check**
   - Mail server configuration

10. **Open Port Scanning**
    - Common ports (80, 443, 22, 21, 25, etc.)
    - Service detection

11. **IPv6 Specific Security Checks**
    - Beyond basic AAAA lookup
    - IPv6-specific vulnerabilities

### **Low Priority - Policy Files**

12. **security.txt File**
    - Check for `/.well-known/security.txt`
    - Security contact information

13. **robots.txt Analysis**
    - Check for information disclosure
    - Verify proper configuration

### **Low Priority - Advanced Checks**

14. **Certificate Chain Validation**
    - Full chain verification (not just leaf)
    - Intermediate certificate checks

15. **OCSP/CRL Checking**
    - Certificate revocation status
    - Real-time validity checking

16. **Subdomain Enumeration**
    - Discover subdomains
    - Check for vulnerable subdomains

17. **CDN/WAF Detection**
    - Identify protective services
    - Cloudflare, Akamai, etc.

---

## Architecture Considerations

### Current Pattern
- Each scanner is independent (identity.go, certificates.go, misconfigurations.go)
- Scanners run in parallel via orchestrator
- Results aggregated into unified Report model
- Graceful degradation if individual checks fail

### For New Checks
- **Group by logical domain**: DNS checks, TLS checks, HTTP checks, Email checks
- **Maintain parallelism**: Don't break existing concurrent execution
- **Update models**: Extend Identity, Certificates, or Misconfigurations structs
- **Preserve minimalism**: Keep output clean and focused

### Files to Modify
- `pkg/models/report.go` - Add new fields to existing structs
- `internal/scanner/identity.go` - DNS/WHOIS checks
- `internal/scanner/certificates.go` - TLS/SSL checks
- `internal/scanner/misconfigurations.go` - Policy/configuration checks
- `internal/renderer/ansi.go` - Display new data
- Test files for each scanner

---

## Implementation Details

### Dependencies

**New Libraries Required:**
- `github.com/miekg/dns` (v1.1.57) - DNSSEC validation, CAA records
- `github.com/likexian/whois` (v1.15.1) - WHOIS data fetching
- `github.com/likexian/whois-parser` (v1.24.9) - WHOIS parsing

**Rationale:** Well-established libraries with active maintenance, minimal dependency trees, no known CVEs.

---

### Model Changes (Backwards Compatible)

All new fields use `omitempty` - zero impact on existing JSON consumers.

```go
// pkg/models/report.go

type Identity struct {
    // Existing fields...

    // NEW - DNSSEC
    DNSSECEnabled bool   `json:"dnssec_enabled,omitempty"`
    DNSSECValid   bool   `json:"dnssec_valid,omitempty"`
    DNSSECError   string `json:"dnssec_error,omitempty"`

    // NEW - CAA
    CAARecords []string `json:"caa_records,omitempty"`
    CAAMissing bool     `json:"caa_missing,omitempty"`
}

type Certificates struct {
    // Existing fields...

    // NEW - TLS Analysis
    TLSVersions      []string `json:"tls_versions,omitempty"`
    WeakTLSVersions  []string `json:"weak_tls_versions,omitempty"`
    CipherSuites     []string `json:"cipher_suites,omitempty"`
    WeakCipherSuites []string `json:"weak_cipher_suites,omitempty"`
}

type Misconfigurations struct {
    // Existing fields...

    // NEW - HTTPS Redirect
    HTTPSRedirect HTTPSRedirectCheck `json:"https_redirect,omitempty"`
}

type HTTPSRedirectCheck struct {
    Enabled      bool   `json:"enabled"`
    StatusCode   int    `json:"status_code,omitempty"`
    FinalURL     string `json:"final_url,omitempty"`
    RedirectLoop bool   `json:"redirect_loop,omitempty"`
    Error        string `json:"error,omitempty"`
}
```

---

### Scanner Assignments

| Feature | Scanner | Implementation |
|---------|---------|----------------|
| DNSSEC Validation | `identity.go` | Query DNSKEY/DS records, validate RRSIG |
| CAA Records | `identity.go` | Query CAA records, walk to parent if needed |
| Complete WHOIS | `identity.go` | Fetch and parse registrar/owner/expiration |
| TLS Protocol/Cipher | `certificates.go` | Test TLS 1.0-1.3, enumerate cipher suites |
| HTTP→HTTPS Redirect | `misconfigurations.go` | Test redirect chain, detect loops |

---

### Implementation Order

**Phase 1 - Foundation:**
1. Add dependencies to `go.mod`
2. Update model structs in `pkg/models/report.go`
3. Create helper files: `dnssec.go`, `caa.go`, `whois.go`, `tls_analyzer.go`, `redirect.go`

**Phase 2 - DNS Security:**
4. Implement CAA record checking (simpler, stdlib-based)
5. Implement DNSSEC validation (uses miekg/dns)
6. Update `identity.go` to call both checks

**Phase 3 - WHOIS:**
7. Implement WHOIS fetching and parsing
8. Populate Registrar, Owner, ExpiresDays fields

**Phase 4 - TLS Analysis:**
9. Implement TLS version testing (1.0, 1.1, 1.2, 1.3)
10. Implement cipher suite enumeration
11. Add weak protocol/cipher detection

**Phase 5 - HTTPS Redirect:**
12. Implement redirect testing with loop detection
13. Update `misconfigurations.go`

**Phase 6 - Rendering:**
14. Update `ansi.go` to display all new checks
15. Add sections for DNSSEC, CAA, TLS, HTTPS redirect

**Phase 7 - Testing:**
16. Unit tests for each new check
17. Integration tests with real domains
18. Performance benchmarking

---

### Performance Impact

**Current:** 3-5 seconds total (parallel execution)

**After Changes:**
- Identity scanner: 5-7s (+DNSSEC, +CAA, +WHOIS)
- Certificate scanner: 3-4s (+TLS analysis)
- Misconfigurations scanner: 4-6s (+HTTPS redirect)

**Total: 7-9 seconds** (still within 10s target)

**Mitigation:**
- Aggressive timeouts (5-10s per scanner)
- WHOIS gets dedicated 3s timeout
- Graceful degradation on all failures

---

### Critical Files

**Models:**
- `pkg/models/report.go` - Add new fields

**Scanners:**
- `internal/scanner/identity.go` - DNSSEC, CAA, WHOIS
- `internal/scanner/certificates.go` - TLS analysis
- `internal/scanner/misconfigurations.go` - HTTPS redirect

**New Helper Files:**
- `internal/scanner/dnssec.go` - DNSSEC validation logic
- `internal/scanner/caa.go` - CAA record checking
- `internal/scanner/whois.go` - WHOIS operations
- `internal/scanner/tls_analyzer.go` - TLS protocol/cipher analysis
- `internal/scanner/redirect.go` - HTTPS redirect checking

**Rendering:**
- `internal/renderer/ansi.go` - Display new security data

**Config:**
- `go.mod` - Add dependencies

---

### Risk Assessment

- ✅ **Low Risk:** Model changes (backwards compatible)
- ✅ **Low Risk:** CAA, HTTPS redirect (stdlib, simple)
- ⚠️ **Medium Risk:** DNSSEC (complex validation, external lib)
- ⚠️ **Medium Risk:** TLS analysis (multiple connections)
- ⚠️ **Medium Risk:** WHOIS (rate limiting, parsing reliability)

---

### Next Steps

1. **Review this plan** - Ensure alignment with your vision
2. **Confirm approach** - Any changes to scope or priorities?
3. **Exit plan mode** - Begin implementation

**Note:** In plan mode, I can only write to the plan file at `/Users/adam/.claude/plans/rippling-dazzling-ember.md`. After exiting plan mode, I can copy this to `.agents/` if needed.
