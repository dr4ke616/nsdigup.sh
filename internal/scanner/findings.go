package scanner

import (
	"context"
	"fmt"
	"time"

	"checks/pkg/models"
)

type FindingsScanner struct {
	timeout time.Duration
}

func NewFindingsScanner(timeout time.Duration) *FindingsScanner {
	return &FindingsScanner{
		timeout: timeout,
	}
}

func (m *FindingsScanner) ScanFindings(ctx context.Context, domain string) (*models.Findings, error) {
	findings := &models.Findings{
		DNSGlue:  []string{},
		Headers:  []string{},
		EmailSec: models.EmailSec{},
	}

	errChan := make(chan error, 3)
	emailDone := make(chan bool, 1)
	headersDone := make(chan bool, 1)
	redirectChan := make(chan RedirectResult, 1)

	go func() {
		emailSec, err := CheckEmailSecurity(ctx, domain)
		if err != nil {
			errChan <- err
		} else {
			findings.EmailSec = emailSec
		}
		emailDone <- true
	}()

	go func() {
		headers, err := CheckSecurityHeaders(ctx, domain, m.timeout)
		if err != nil {
			errChan <- err
		} else {
			findings.Headers = headers
		}
		headersDone <- true
	}()

	go func() {
		result := CheckHTTPSRedirect(ctx, domain, m.timeout)
		redirectChan <- result
	}()

	timeout := time.NewTimer(m.timeout)
	defer timeout.Stop()

	var redirectResult RedirectResult

	for i := 0; i < 3; i++ {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		case <-timeout.C:
			return findings, fmt.Errorf("findings scan timeout")
		case <-emailDone:
		case <-headersDone:
		case redirect := <-redirectChan:
			redirectResult = redirect
		case <-errChan:
		}
	}

	// Set HTTPS redirect results
	findings.HTTPSRedirect = models.HTTPSRedirectCheck{
		Enabled:      redirectResult.Enabled,
		StatusCode:   redirectResult.StatusCode,
		FinalURL:     redirectResult.FinalURL,
		RedirectLoop: redirectResult.RedirectLoop,
		Error:        redirectResult.Error,
	}

	return findings, nil
}
