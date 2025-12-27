package tools

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DNSSECResult contains the results of DNSSEC validation
type DNSSECResult struct {
	Enabled bool
	Valid   bool
	Error   string
}

// CAAResult contains the results of CAA record checking
type CAAResult struct {
	Records []string
	Missing bool
	Error   error
}

// CheckDNSSEC validates DNSSEC signatures for a domain
func CheckDNSSEC(ctx context.Context, domain string, timeout time.Duration) DNSSECResult {
	result := DNSSECResult{
		Enabled: false,
		Valid:   false,
	}

	domain = normalizeDomain(domain)

	// Create DNS client with timeout
	client := &dns.Client{
		Timeout: timeout,
	}

	// Step 1: Check if DNSSEC is enabled by looking for DNSKEY records
	dnskeyExists, err := hasDNSKEY(ctx, client, domain)
	if err != nil {
		result.Error = fmt.Sprintf("DNSKEY query failed: %v", err)
		return result
	}

	if !dnskeyExists {
		// DNSSEC not enabled
		result.Enabled = false
		return result
	}

	result.Enabled = true

	// Step 2: Validate DNSSEC chain by checking RRSIG records
	valid, err := validateDNSSEC(ctx, client, domain)
	if err != nil {
		result.Error = fmt.Sprintf("DNSSEC validation failed: %v", err)
		return result
	}

	result.Valid = valid
	return result
}

// CheckCAA queries CAA records for a domain, walking up to parent domains if necessary
func CheckCAA(ctx context.Context, domain string, timeout time.Duration) CAAResult {
	result := CAAResult{
		Records: []string{},
		Missing: false,
	}

	// Create DNS client with timeout
	client := &dns.Client{
		Timeout: timeout,
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

// validateDNSSEC validates DNSSEC signatures by checking RRSIG records
func validateDNSSEC(ctx context.Context, client *dns.Client, domain string) (bool, error) {
	// Query for A record with DNSSEC validation
	msg := &dns.Msg{}
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	msg.SetEdns0(4096, true)     // Enable EDNS0
	msg.AuthenticatedData = true // Request authenticated data
	msg.CheckingDisabled = false // Enable DNSSEC checking

	// Use a DNSSEC-validating resolver (Google's 8.8.8.8 validates DNSSEC)
	resp, _, err := client.ExchangeContext(ctx, msg, "8.8.8.8:53")
	if err != nil {
		return false, err
	}

	if resp == nil {
		return false, fmt.Errorf("no response received")
	}

	// Check for RRSIG records in the response
	hasRRSIG := false
	for _, ans := range resp.Answer {
		if _, ok := ans.(*dns.RRSIG); ok {
			hasRRSIG = true
			break
		}
	}

	// If we got RRSIG records and the AD (Authenticated Data) bit is set,
	// the resolver has validated the DNSSEC chain
	if hasRRSIG && resp.AuthenticatedData {
		return true, nil
	}

	// If we have DNSKEY but no valid RRSIG, DNSSEC might be misconfigured
	if !hasRRSIG {
		return false, fmt.Errorf("DNSSEC enabled but no RRSIG records found")
	}

	// If we have RRSIG but AD bit not set, validation failed
	if hasRRSIG && !resp.AuthenticatedData {
		return false, fmt.Errorf("DNSSEC signatures present but validation failed")
	}

	return false, nil
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

// hasDNSKEY checks if a domain has DNSKEY records (indicating DNSSEC is enabled)
func hasDNSKEY(ctx context.Context, client *dns.Client, domain string) (bool, error) {
	msg := &dns.Msg{}
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeDNSKEY)
	msg.SetEdns0(4096, true) // Enable DNSSEC with EDNS0

	resp, _, err := client.ExchangeContext(ctx, msg, "8.8.8.8:53")
	if err != nil {
		return false, err
	}

	if resp == nil {
		return false, fmt.Errorf("no response received")
	}

	// Check if we got DNSKEY records
	for _, ans := range resp.Answer {
		if _, ok := ans.(*dns.DNSKEY); ok {
			return true, nil
		}
	}

	return false, nil
}
