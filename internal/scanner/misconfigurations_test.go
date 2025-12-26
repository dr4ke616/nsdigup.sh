package scanner

import (
	"context"
	"testing"
	"time"
)

func TestMisconfigurationScanner_ScanMisconfigurations(t *testing.T) {
	scanner := NewMisconfigurationScanner()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	tests := []struct {
		name           string
		domain         string
		checkEmail     bool
		checkHeaders   bool
		expectNoErrors bool
	}{
		{
			name:           "Well-configured site - google.com",
			domain:         "google.com",
			checkEmail:     true,
			checkHeaders:   true,
			expectNoErrors: true,
		},
		{
			name:           "Well-configured site - cloudflare.com",
			domain:         "cloudflare.com",
			checkEmail:     true,
			checkHeaders:   true,
			expectNoErrors: true,
		},
		{
			name:           "Test domain - example.com",
			domain:         "example.com",
			checkEmail:     true,
			checkHeaders:   true,
			expectNoErrors: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			misconfigs, err := scanner.ScanMisconfigurations(ctx, tt.domain)

			if err != nil && tt.expectNoErrors {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if misconfigs == nil {
				t.Error("Expected misconfigurations object but got nil")
				return
			}

			if tt.checkEmail {
				t.Logf("Email Security for %s:", tt.domain)
				t.Logf("  SPF: %s", misconfigs.EmailSec.SPF)
				t.Logf("  DMARC: %s", misconfigs.EmailSec.DMARC)
				t.Logf("  IsWeak: %v", misconfigs.EmailSec.IsWeak)
			}

			if tt.checkHeaders {
				t.Logf("Header Issues for %s: %d issues", tt.domain, len(misconfigs.Headers))
				for _, issue := range misconfigs.Headers {
					t.Logf("  - %s", issue)
				}
			}
		})
	}
}

func TestMisconfigurationScanner_EmailSecurity(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		domain         string
		expectSPF      bool
		expectDMARC    bool
		skipIfNoRecord bool
	}{
		{
			domain:      "google.com",
			expectSPF:   true,
			expectDMARC: true,
		},
		{
			domain:      "github.com",
			expectSPF:   true,
			expectDMARC: true,
		},
		{
			domain:         "example.com",
			expectSPF:      false,
			expectDMARC:    false,
			skipIfNoRecord: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			emailSec, err := CheckEmailSecurity(ctx, tt.domain)
			if err != nil {
				t.Errorf("Error checking email security: %v", err)
				return
			}

			if tt.expectSPF && emailSec.SPF == "" {
				if !tt.skipIfNoRecord {
					t.Errorf("Expected SPF record for %s but got none", tt.domain)
				}
			}

			if emailSec.SPF != "" && !emailSec.IsWeak {
				if !startsWith(emailSec.SPF, "v=spf1") {
					t.Errorf("Invalid SPF record format: %s", emailSec.SPF)
				}
			}

			if tt.expectDMARC && emailSec.DMARC == "none" && emailSec.SPF != "" {
				t.Logf("Note: %s has SPF but DMARC policy is 'none'", tt.domain)
			}

			validDMARC := []string{"none", "quarantine", "reject", ""}
			dmarcValid := false
			for _, policy := range validDMARC {
				if emailSec.DMARC == policy {
					dmarcValid = true
					break
				}
			}
			if !dmarcValid {
				t.Errorf("Invalid DMARC policy: %s", emailSec.DMARC)
			}

			if emailSec.DMARC == "none" && !emailSec.IsWeak {
				t.Error("DMARC policy is 'none' but IsWeak is false")
			}
		})
	}
}

func TestMisconfigurationScanner_Headers(t *testing.T) {
	ctx := context.Background()

	importantHeaders := []string{
		"HSTS",
		"CSP",
		"X-Frame-Options",
		"X-Content-Type-Options",
		"Referrer-Policy",
		"Permissions-Policy",
	}

	domains := []string{"google.com", "github.com", "cloudflare.com"}

	for _, domain := range domains {
		t.Run(domain, func(t *testing.T) {
			headers, err := CheckSecurityHeaders(ctx, domain)
			if err != nil {
				t.Logf("Could not check headers for %s: %v", domain, err)
				return
			}

			t.Logf("Security header analysis for %s:", domain)
			t.Logf("  Total issues found: %d", len(headers))

			missingHeaders := make(map[string]bool)
			for _, header := range importantHeaders {
				missingHeaders[header] = true
			}

			for _, issue := range headers {
				t.Logf("  - %s", issue)
				for header := range missingHeaders {
					if contains(issue, header) {
						delete(missingHeaders, header)
					}
				}
			}

			if len(missingHeaders) < len(importantHeaders) {
				t.Logf("  %s implements %d/%d security headers",
					domain,
					len(importantHeaders)-len(missingHeaders),
					len(importantHeaders))
			}
		})
	}
}

func TestMisconfigurationScanner_ContextTimeout(t *testing.T) {
	scanner := NewMisconfigurationScanner()
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	time.Sleep(10 * time.Millisecond)

	_, err := scanner.ScanMisconfigurations(ctx, "google.com")
	if err == nil {
		t.Error("Expected timeout error but got none")
	}
}

func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
