package models

import "time"

type Report struct {
	Target       string       `json:"target"`
	Timestamp    time.Time    `json:"timestamp"`
	Identity     Identity     `json:"identity"`
	Certificates Certificates `json:"certificates"`
	Findings     Findings     `json:"findings"`
}

type Identity struct {
	IP            string    `json:"ip_address"`
	Registrar     string    `json:"registrar"`
	Owner         string    `json:"owner"`
	ExpiresAt     time.Time `json:"expires_at,omitempty"`
	ExpiresInDays int       `json:"expires_in_days,omitempty"`
	Nameservers   []string  `json:"nameservers"`

	// DNSSEC validation
	DNSSECEnabled bool   `json:"dnssec_enabled,omitempty"`
	DNSSECValid   bool   `json:"dnssec_valid,omitempty"`
	DNSSECError   string `json:"dnssec_error,omitempty"`

	// CAA records
	CAARecords []string `json:"caa_records,omitempty"`
	CAAMissing bool     `json:"caa_missing,omitempty"`
}

type Certificates struct {
	Issuer        string    `json:"issuer"`
	CommonName    string    `json:"common_name"`
	ExpiresAt     time.Time `json:"expires_at"`
	ExpiresInDays int       `json:"expires_in_days"`
	Status        string    `json:"status"`
	IsWildcard    bool      `json:"is_wildcard"`
	IsSelfSigned  bool      `json:"is_self_signed"`

	// TLS protocol and cipher analysis
	TLSVersions      []string `json:"tls_versions,omitempty"`
	WeakTLSVersions  []string `json:"weak_tls_versions,omitempty"`
	CipherSuites     []string `json:"cipher_suites,omitempty"`
	WeakCipherSuites []string `json:"weak_cipher_suites,omitempty"`
}

type Findings struct {
	HTTP  HTTPFindings  `json:"http"`
	Email EmailFindings `json:"email"`
}

type EmailFindings struct {
	EmailSec EmailSec `json:"email_security"`
}

type HTTPFindings struct {
	Headers       []string           `json:"header_issues"`
	HTTPSRedirect HTTPSRedirectCheck `json:"https_redirect,omitempty"`
}

type EmailSec struct {
	DMARC  string `json:"dmarc_policy"`
	SPF    string `json:"spf_record"`
	IsWeak bool   `json:"is_weak"`
}

type HTTPSRedirectCheck struct {
	Enabled      bool   `json:"enabled"`
	StatusCode   int    `json:"status_code,omitempty"`
	FinalURL     string `json:"final_url,omitempty"`
	RedirectLoop bool   `json:"redirect_loop,omitempty"`
	Error        string `json:"error,omitempty"`
}
