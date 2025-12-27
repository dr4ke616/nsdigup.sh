package tools

import (
	"context"
	"fmt"
	"time"

	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
)

// WHOISResult contains the parsed WHOIS information
type WHOISResult struct {
	Registrar   string
	Owner       string
	ExpiresDays int
	Error       error
}

// CheckWHOIS fetches and parses WHOIS data for a domain
func CheckWHOIS(ctx context.Context, domain string, timeout time.Duration) WHOISResult {
	domain = normalizeDomain(domain)

	// Create a channel for the WHOIS operation with timeout
	done := make(chan WHOISResult, 1)

	go func() {
		// Fetch raw WHOIS data
		rawData, err := whois.Whois(domain)
		if err != nil {
			done <- WHOISResult{
				ExpiresDays: -1,
				Error:       fmt.Errorf("WHOIS fetch failed: %w", err),
			}
			return
		}

		// Parse WHOIS data
		parsed, err := whoisparser.Parse(rawData)
		if err != nil {
			done <- WHOISResult{
				ExpiresDays: -1,
				Error:       fmt.Errorf("WHOIS parse failed: %w", err),
			}
			return
		}

		// Extract registrar
		registrar := ""
		if parsed.Registrar != nil {
			registrar = parsed.Registrar.Name
		}

		// Extract owner (registrant organization or name)
		owner := ""
		if parsed.Registrant != nil {
			if parsed.Registrant.Organization != "" {
				owner = parsed.Registrant.Organization
			} else if parsed.Registrant.Name != "" {
				owner = parsed.Registrant.Name
			}
		}

		// Calculate days until expiration
		expiresDays := -1
		if parsed.Domain != nil && parsed.Domain.ExpirationDate != "" {
			expiryDate, err := parseDate(parsed.Domain.ExpirationDate)
			if err == nil {
				daysUntil := int(time.Until(expiryDate).Hours() / 24)
				expiresDays = daysUntil
			}
		}

		done <- WHOISResult{
			Registrar:   registrar,
			Owner:       owner,
			ExpiresDays: expiresDays,
			Error:       nil,
		}
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	// Wait for result or timeout (3 seconds as per plan)
	select {
	case <-ctx.Done():
		return WHOISResult{
			ExpiresDays: -1,
			Error:       fmt.Errorf("WHOIS query timeout"),
		}
	case res := <-done:
		return res
	case <-timer.C:
		return WHOISResult{
			ExpiresDays: -1,
			Error:       fmt.Errorf("WHOIS query timeout after 3s"),
		}
	}
}

// parseDate attempts to parse various date formats commonly found in WHOIS data
func parseDate(dateStr string) (time.Time, error) {
	// Common WHOIS date formats
	formats := []string{
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05",
		"2006-01-02",
		"02-Jan-2006",
		"2006.01.02",
		time.RFC3339,
	}

	for _, format := range formats {
		if t, err := time.Parse(format, dateStr); err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("unable to parse date: %s", dateStr)
}
