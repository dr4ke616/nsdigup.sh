package models

import "time"

type Report struct {
	Target            string            `json:"target"`
	Timestamp         time.Time         `json:"timestamp"`
	Identity          Identity          `json:"identity"`
	Certificates      CertData          `json:"certificates"`
	Misconfigurations Misconfigurations `json:"misconfigurations"`
	HTTP              HTTPDetails       `json:"http_details"`
}

type Identity struct {
	IP          string   `json:"ip_address"`
	Registrar   string   `json:"registrar"`
	Owner       string   `json:"owner"`
	ExpiresDays int      `json:"expires_days"`
	Nameservers []string `json:"nameservers"`
}

type CertData struct {
	Current CertDetails   `json:"current"`
	History []CertDetails `json:"history"`
}

type CertDetails struct {
	Issuer     string    `json:"issuer"`
	CommonName string    `json:"common_name"`
	NotAfter   time.Time `json:"expires_at"`
	Status     string    `json:"status"`
	IsWildcard bool      `json:"is_wildcard"`
}

type Misconfigurations struct {
	DNSGlue  []string `json:"dns_glue_issues"`
	EmailSec EmailSec `json:"email_security"`
	Headers  []string `json:"header_issues"`
}

type EmailSec struct {
	DMARC  string `json:"dmarc_policy"`
	SPF    string `json:"spf_record"`
	IsWeak bool   `json:"is_weak"`
}

type HTTPDetails struct {
	StatusCode int `json:"status_code"`
}