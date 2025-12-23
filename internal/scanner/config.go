package scanner

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"checks/pkg/models"
)

type ConfigScanner struct{}

func NewConfigScanner() *ConfigScanner {
	return &ConfigScanner{}
}

func (c *ConfigScanner) ScanMisconfigurations(ctx context.Context, domain string) (*models.Misconfigurations, error) {
	misconfigs := &models.Misconfigurations{
		DNSGlue:  []string{},
		Headers:  []string{},
		EmailSec: models.EmailSec{},
	}

	errChan := make(chan error, 2)
	emailDone := make(chan bool, 1)
	headersDone := make(chan bool, 1)

	go func() {
		emailSec, err := c.checkEmailSecurity(ctx, domain)
		if err != nil {
			errChan <- err
		} else {
			misconfigs.EmailSec = emailSec
		}
		emailDone <- true
	}()

	go func() {
		headers, err := c.checkHeaders(ctx, domain)
		if err != nil {
			errChan <- err
		} else {
			misconfigs.Headers = headers
		}
		headersDone <- true
	}()

	timeout := time.NewTimer(10 * time.Second)
	defer timeout.Stop()

	for i := 0; i < 2; i++ {
		select {
		case <-ctx.Done():
			return misconfigs, ctx.Err()
		case <-timeout.C:
			return misconfigs, fmt.Errorf("config scan timeout")
		case <-emailDone:
		case <-headersDone:
		case <-errChan:
		}
	}

	return misconfigs, nil
}

func (c *ConfigScanner) checkEmailSecurity(ctx context.Context, domain string) (models.EmailSec, error) {
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
	}
	if emailSec.DMARC == "" {
		emailSec.DMARC = "none"
		emailSec.IsWeak = true
	}

	return emailSec, nil
}

func (c *ConfigScanner) checkHeaders(ctx context.Context, domain string) ([]string, error) {
	issues := []string{}

	client := &http.Client{
		Timeout: 5 * time.Second,
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