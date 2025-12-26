package models

import "time"

type Report struct {
	Target            string            `json:"target"`
	Timestamp         time.Time         `json:"timestamp"`
	Identity          Identity          `json:"identity"`
	Certificates      Certificates      `json:"certificates"`
	Misconfigurations Misconfigurations `json:"misconfigurations"`
	HTTP              HTTPDetails       `json:"http_details"`
}

type Identity struct {
	IP          string   `json:"ip_address"`
	Registrar   string   `json:"registrar"`
	Owner       string   `json:"owner"`
	ExpiresDays int      `json:"expires_days"`
	Nameservers []string `json:"nameservers"`

	// DNSSEC validation
	DNSSECEnabled bool   `json:"dnssec_enabled,omitempty"`
	DNSSECValid   bool   `json:"dnssec_valid,omitempty"`
	DNSSECError   string `json:"dnssec_error,omitempty"`

	// CAA records
	CAARecords []string `json:"caa_records,omitempty"`
	CAAMissing bool     `json:"caa_missing,omitempty"`
}

type Certificates struct {
	Issuer     string    `json:"issuer"`
	CommonName string    `json:"common_name"`
	NotAfter   time.Time `json:"expires_at"`
	Status     string    `json:"status"`
	IsWildcard bool      `json:"is_wildcard"`

	// TLS protocol and cipher analysis
	TLSVersions      []string `json:"tls_versions,omitempty"`
	WeakTLSVersions  []string `json:"weak_tls_versions,omitempty"`
	CipherSuites     []string `json:"cipher_suites,omitempty"`
	WeakCipherSuites []string `json:"weak_cipher_suites,omitempty"`
}

type Misconfigurations struct {
	DNSGlue  []string `json:"dns_glue_issues"`
	EmailSec EmailSec `json:"email_security"`
	Headers  []string `json:"header_issues"`

	// HTTPS redirect checking
	HTTPSRedirect HTTPSRedirectCheck `json:"https_redirect,omitempty"`
}

type EmailSec struct {
	DMARC  string `json:"dmarc_policy"`
	SPF    string `json:"spf_record"`
	IsWeak bool   `json:"is_weak"`
}

type HTTPDetails struct {
	StatusCode int `json:"status_code"`
}

type HTTPSRedirectCheck struct {
	Enabled      bool   `json:"enabled"`
	StatusCode   int    `json:"status_code,omitempty"`
	FinalURL     string `json:"final_url,omitempty"`
	RedirectLoop bool   `json:"redirect_loop,omitempty"`
	Error        string `json:"error,omitempty"`
}
