package tools

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"checks/internal/logger"
	"checks/pkg/models"
)

// CheckEmailSecurity analyzes SPF and DMARC records for the given domain.
// It identifies weak or missing email security configurations that could
// allow email spoofing or phishing attacks.
func CheckEmailSecurity(ctx context.Context, domain string) (models.EmailSec, error) {
	emailSec := models.EmailSec{}

	resolver := &net.Resolver{}

	spfRecords, _ := resolver.LookupTXT(ctx, domain)
	for _, txt := range spfRecords {
		if strings.HasPrefix(txt, "v=spf1") {
			emailSec.SPF = txt
			if strings.Contains(txt, "+all") || strings.Contains(txt, "?all") {
				emailSec.IsWeak = true
			}
			break
		}
	}

	dmarcRecords, _ := resolver.LookupTXT(ctx, fmt.Sprintf("_dmarc.%s", domain))
	for _, txt := range dmarcRecords {
		if strings.HasPrefix(txt, "v=DMARC1") {
			if strings.Contains(txt, "p=none") {
				emailSec.DMARC = "none"
				emailSec.IsWeak = true
			} else if strings.Contains(txt, "p=quarantine") {
				emailSec.DMARC = "quarantine"
			} else if strings.Contains(txt, "p=reject") {
				emailSec.DMARC = "reject"
			}
			break
		}
	}

	if emailSec.SPF == "" {
		emailSec.IsWeak = true
		logger.Get().Debug("SPF record missing",
			slog.String("domain", domain))
	}
	if emailSec.DMARC == "" || emailSec.DMARC == "none" {
		if emailSec.DMARC == "" {
			emailSec.DMARC = "none"
		}
		emailSec.IsWeak = true
		logger.Get().Debug("weak DMARC policy",
			slog.String("domain", domain),
			slog.String("policy", emailSec.DMARC))
	}

	return emailSec, nil
}

// CheckSecurityHeaders performs an HTTP request to the domain and checks for
// security-related HTTP headers (HSTS, CSP, X-Frame-Options, etc.).
// Returns a list of security issues found.
func CheckSecurityHeaders(ctx context.Context, domain string, timeout time.Duration) ([]string, error) {
	issues := []string{}

	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, "HEAD", fmt.Sprintf("https://%s", domain), nil)
	if err != nil {
		return issues, err
	}

	resp, err := client.Do(req)
	if err != nil {
		req.URL.Scheme = "http"
		resp, err = client.Do(req)
		if err != nil {
			return issues, fmt.Errorf("HTTP request failed: %w", err)
		}
	}
	defer resp.Body.Close()

	if resp.Header.Get("Strict-Transport-Security") == "" {
		issues = append(issues, "Missing HSTS header")
	}

	csp := resp.Header.Get("Content-Security-Policy")
	if csp == "" {
		issues = append(issues, "Missing CSP header")
	} else if strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") {
		issues = append(issues, "Weak CSP policy (contains unsafe-inline or unsafe-eval)")
	}

	if resp.Header.Get("X-Frame-Options") == "" && !strings.Contains(csp, "frame-ancestors") {
		issues = append(issues, "Missing X-Frame-Options header")
	}

	if resp.Header.Get("X-Content-Type-Options") == "" {
		issues = append(issues, "Missing X-Content-Type-Options header")
	}

	if resp.Header.Get("Referrer-Policy") == "" {
		issues = append(issues, "Missing Referrer-Policy header")
	}

	permissionsPolicy := resp.Header.Get("Permissions-Policy")
	if permissionsPolicy == "" {
		permissionsPolicy = resp.Header.Get("Feature-Policy")
	}
	if permissionsPolicy == "" {
		issues = append(issues, "Missing Permissions-Policy header")
	}

	return issues, nil
}
