package tools

import (
	"context"
	"fmt"
	"time"

	"github.com/miekg/dns"
)

// DNSSECResult contains the results of DNSSEC validation
type DNSSECResult struct {
	Enabled bool
	Valid   bool
	Error   string
}

// CheckDNSSEC validates DNSSEC signatures for a domain
func CheckDNSSEC(ctx context.Context, domain string) DNSSECResult {
	result := DNSSECResult{
		Enabled: false,
		Valid:   false,
	}

	domain = normalizeDomain(domain)

	// Create DNS client with timeout
	client := &dns.Client{
		Timeout: 5 * time.Second,
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
