package scanner

import (
	"context"
	"fmt"
	"time"

	"checks/pkg/models"
)

type MisconfigurationScanner struct{}

func NewMisconfigurationScanner() *MisconfigurationScanner {
	return &MisconfigurationScanner{}
}

func (m *MisconfigurationScanner) ScanMisconfigurations(ctx context.Context, domain string) (*models.Misconfigurations, error) {
	misconfigs := &models.Misconfigurations{
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
			misconfigs.EmailSec = emailSec
		}
		emailDone <- true
	}()

	go func() {
		headers, err := CheckSecurityHeaders(ctx, domain)
		if err != nil {
			errChan <- err
		} else {
			misconfigs.Headers = headers
		}
		headersDone <- true
	}()

	go func() {
		result := CheckHTTPSRedirect(ctx, domain)
		redirectChan <- result
	}()

	timeout := time.NewTimer(10 * time.Second)
	defer timeout.Stop()

	var redirectResult RedirectResult

	for i := 0; i < 3; i++ {
		select {
		case <-ctx.Done():
			return misconfigs, ctx.Err()
		case <-timeout.C:
			return misconfigs, fmt.Errorf("misconfiguration scan timeout")
		case <-emailDone:
		case <-headersDone:
		case redirect := <-redirectChan:
			redirectResult = redirect
		case <-errChan:
		}
	}

	// Set HTTPS redirect results
	misconfigs.HTTPSRedirect = models.HTTPSRedirectCheck{
		Enabled:      redirectResult.Enabled,
		StatusCode:   redirectResult.StatusCode,
		FinalURL:     redirectResult.FinalURL,
		RedirectLoop: redirectResult.RedirectLoop,
		Error:        redirectResult.Error,
	}

	return misconfigs, nil
}
