package tools

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// CAAResult contains the results of CAA record checking
type CAAResult struct {
	Records []string
	Missing bool
	Error   error
}

// CheckCAA queries CAA records for a domain, walking up to parent domains if necessary
func CheckCAA(ctx context.Context, domain string) CAAResult {
	result := CAAResult{
		Records: []string{},
		Missing: false,
	}

	// Create DNS client with timeout
	client := &dns.Client{
		Timeout: 5 * time.Second,
	}

	// Try the domain and walk up to parent domains
	currentDomain := normalizeDomain(domain)
	for {
		records, err := queryCAARecords(ctx, client, currentDomain)
		if err != nil {
			result.Error = err
			return result
		}

		if len(records) > 0 {
			result.Records = records
			result.Missing = false
			return result
		}

		// Walk up to parent domain
		parent := getParentDomain(currentDomain)
		if parent == "" || parent == currentDomain {
			// Reached the top-level domain without finding CAA records
			break
		}
		currentDomain = parent
	}

	// No CAA records found at any level
	result.Missing = true
	return result
}

// queryCAARecords queries CAA records for a specific domain
func queryCAARecords(ctx context.Context, client *dns.Client, domain string) ([]string, error) {
	msg := &dns.Msg{}
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeCAA)
	msg.RecursionDesired = true

	// Use Google's public DNS (8.8.8.8) as resolver
	resp, _, err := client.ExchangeContext(ctx, msg, "8.8.8.8:53")
	if err != nil {
		return nil, fmt.Errorf("CAA query failed: %w", err)
	}

	if resp == nil || resp.Rcode != dns.RcodeSuccess {
		return nil, nil // No error, just no records
	}

	var caaRecords []string
	for _, ans := range resp.Answer {
		if caa, ok := ans.(*dns.CAA); ok {
			// Format: "tag value" (e.g., "issue letsencrypt.org")
			record := fmt.Sprintf("%s %s", caa.Tag, caa.Value)
			caaRecords = append(caaRecords, record)
		}
	}

	return caaRecords, nil
}

// normalizeDomain removes common prefixes like www. and ensures proper format
func normalizeDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))

	// Remove protocol if present
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")

	// Remove port if present
	if idx := strings.Index(domain, ":"); idx != -1 {
		domain = domain[:idx]
	}

	// Remove trailing dot
	domain = strings.TrimSuffix(domain, ".")

	return domain
}

// getParentDomain returns the parent domain (e.g., "sub.example.com" -> "example.com")
func getParentDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) <= 2 {
		// Already at TLD or invalid
		return ""
	}
	return strings.Join(parts[1:], ".")
}
