package scanner

import (
	"context"
	"fmt"
	"time"

	"nsdigup/internal/scanner/tools"
	"nsdigup/pkg/models"
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
	emailFindings := &models.EmailFindings{}
	httpFindings := &models.HTTPFindings{}

	errChan := make(chan error, 3)
	emailDone := make(chan bool, 1)
	headersDone := make(chan bool, 1)
	redirectChan := make(chan tools.RedirectResult, 1)

	go func() {
		emailSec, err := tools.CheckEmailSecurity(ctx, domain)
		if err != nil {
			errChan <- err
		} else {
			emailFindings.EmailSec = emailSec
		}
		emailDone <- true
	}()

	go func() {
		headers, err := tools.CheckHttpSecurityHeaders(ctx, domain, m.timeout)
		if err != nil {
			errChan <- err
		} else {
			httpFindings.Headers = headers
		}
		headersDone <- true
	}()

	go func() {
		result := tools.CheckHTTPSRedirect(ctx, domain, m.timeout)
		redirectChan <- result
	}()

	timer := time.NewTimer(m.timeout)
	defer timer.Stop()

	findings := &models.Findings{HTTP: *httpFindings, Email: *emailFindings}

	var redirectResult tools.RedirectResult
	for range 3 {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		case <-timer.C:
			return findings, fmt.Errorf("findings scan timeout")
		case <-emailDone:
		case <-headersDone:
		case redirect := <-redirectChan:
			redirectResult = redirect
		case <-errChan:
		}
	}

	// Set HTTPS redirect results
	httpFindings.HTTPSRedirect = models.HTTPSRedirectCheck{
		Enabled:      redirectResult.Enabled,
		StatusCode:   redirectResult.StatusCode,
		FinalURL:     redirectResult.FinalURL,
		RedirectLoop: redirectResult.RedirectLoop,
		Error:        redirectResult.Error,
	}

	findings.HTTP = *httpFindings
	findings.Email = *emailFindings

	return findings, nil
}
