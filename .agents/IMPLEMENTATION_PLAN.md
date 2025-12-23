# Implementation Plan: checks.sh (MVP)

## 1. Project Overview
**Goal:** Create a curl-first domain health utility in Go.
**Core Function:** Aggregates Domain Identity, Certificate Health, and Configuration gaps into a high-density ANSI report.
**Constraints:** Standard library only, In-Memory caching, clean architecture, <2s response time.
**MVP Scope:** Focus on DNS, Active SSL, and basic Headers. WHOIS and deep Cert History are modeled but implemented in later phases.

## 2. Directory Structure & File Organization
Adhering to the Standard Go Project Layout.

```text
checks/
├── cmd/
│   └── checks/
│       └── main.go           # Application Entry Point
├── internal/
│   ├── server/
│   │   ├── handler.go        # HTTP Handlers (Controller)
│   │   └── middleware.go     # Logging & Recovery
│   ├── scanner/
│   │   ├── orchestrator.go   # Manages concurrent scans
│   │   ├── dns.go            # Identity/IP resolution
│   │   ├── ssl.go            # Certificate analysis
│   │   └── config.go         # Misconfiguration checks (Headers/DNS Glue)
│   ├── cache/
│   │   └── memory.go         # Thread-safe in-memory store
│   └── renderer/
│       ├── ansi.go           # Terminal output logic
│       └── json.go           # JSON output logic
└── pkg/
    └── models/
        └── report.go         # Shared data structs

```

## 3. Data Models (`pkg/models`)

The central data structure used to pass data between Scanner -> Cache -> Renderer.

```go
type Report struct {
    Target          string            `json:"target"`
    Timestamp       time.Time         `json:"timestamp"`
    Identity        Identity          `json:"identity"`
    Certificates    CertData          `json:"certificates"`
    Misconfigurations Misconfigurations `json:"misconfigurations"`
    HTTP            HTTPDetails       `json:"http_details"` // Reserved for Phase 3+
}

// 1. Identity (The "Who")
type Identity struct {
    IP          string   `json:"ip_address"`
    Registrar   string   `json:"registrar"`       // Reserved for Phase 2 (Whois)
    Owner       string   `json:"owner"`           // Reserved for Phase 2 (Whois)
    ExpiresDays int      `json:"expires_days"`    // Reserved for Phase 2 (Whois)
    Nameservers []string `json:"nameservers"`
}

// 2. Certificate Info & History (The "What")
type CertData struct {
    Current  CertDetails   `json:"current"`
    History  []CertDetails `json:"history"`       // Reserved for Phase 2 (CT Logs)
}

type CertDetails struct {
    Issuer     string    `json:"issuer"`
    CommonName string    `json:"common_name"`
    NotAfter   time.Time `json:"expires_at"`
    Status     string    `json:"status"`          // e.g., "Active", "Expired"
    IsWildcard bool      `json:"is_wildcard"`
}

// 3. Misconfigurations (The "How")
type Misconfigurations struct {
    DNSGlue   []string  `json:"dns_glue_issues"`  // Dangling CNAMEs etc.
    EmailSec  EmailSec  `json:"email_security"`   // SPF/DMARC
    Headers   []string  `json:"header_issues"`    // Missing HSTS, CSP, etc.
}

type EmailSec struct {
    DMARC   string `json:"dmarc_policy"`          // e.g., "reject", "none"
    SPF     string `json:"spf_record"`
    IsWeak  bool   `json:"is_weak"`
}

// 4. HTTP (Reserved)
type HTTPDetails struct {
    StatusCode int `json:"status_code"`
}
```

## 4. Component Interfaces

### Scanner Interface (`internal/scanner`)

```go
type Scanner interface {
    // Scan performs all checks concurrently
    Scan(ctx context.Context, domain string) (*models.Report, error)
}
```

### Cache Interface (`internal/cache`)

```go
type Store interface {
    Get(domain string) (*models.Report, bool)
    Set(domain string, report *models.Report)
}
```

### Renderer Interface (`internal/renderer`)

```go
type Renderer interface {
    Render(w io.Writer, report *models.Report) error
}
```

## 5. Implementation Phases

### Phase 1: Foundation & Wiring

* [ ] Initialize `go.mod`.
* [ ] Create `pkg/models/report.go` with the updated structs.
* [ ] Create `internal/server/handler.go` and `cmd/dom/main.go`.
* [ ] **Verification:** Server accepts connections and maps a request to an empty Report struct.

### Phase 2: The Scanner (Backend Logic)

* [ ] **Identity Module (`dns.go`):** Implement `net.LookupIP` and `net.LookupNS` to populate `Identity.IP` and `Identity.Nameservers`. (Leave Registrar/Owner empty).
* [ ] **SSL Module (`ssl.go`):** Implement `tls.Dial` to populate `Certificates.Current`. Calculate `Status` based on `NotAfter`. Check `CommonName` for `*` prefix (`IsWildcard`).
* [ ] **Config Module (`config.go`):**
* **Email:** `net.LookupTXT` to parse SPF/DMARC.
* **Headers:** `http.Head` to check HSTS/CSP. Populate `Misconfigurations.Headers`.
* [ ] **Verification:** Handler outputs JSON dump with real IP, Cert, and Header data.

### Phase 3: Caching & Optimization

* [ ] Implement `internal/cache/memory.go` (Thread-safe map).
* [ ] Integrate Cache into Handler (Read-through cache strategy).

### Phase 4: The Renderer (Presentation)

* [ ] **ANSI Renderer:**
* Create `[ IDENTITY ]`, `[ CERTIFICATES ]`, `[ MISCONFIGURATIONS ]` blocks.
* Logic to hide empty fields (e.g., if Registrar is empty in MVP, do not print the line).
* Colorize "Risks" (e.g., DMARC `p=none` in Red).


* [ ] **JSON Renderer:** Standard marshalling.

## 6. Coding Standards (For Agents)

1. **Stdlib Only:** Strictly no external imports.
2. **Zero-Value Handling:** The Renderer must gracefully handle empty strings/structs since WHOIS/History are delayed to Phase 2.
3. **Concurrency:** Use `sync.WaitGroup` in the `orchestrator` to run Identity, SSL, and Config scans in parallel.
4. **Context:** Pass `context.Context` deep into network calls for cancellation.

