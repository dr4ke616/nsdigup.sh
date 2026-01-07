package scanner

import (
	"context"
	"fmt"
	"time"

	"nsdigup/internal/scanner/tools"
	"nsdigup/pkg/models"
)

type CertificateScanner struct {
	timeout time.Duration
}

func NewCertificateScanner(timeout time.Duration) *CertificateScanner {
	return &CertificateScanner{
		timeout: timeout,
	}
}

func (c *CertificateScanner) ScanCertificates(ctx context.Context, domain string) (*models.Certificates, error) {
	certData := &models.Certificates{}

	// Channel for parallel checks
	certChan := make(chan tools.CertInfo, 1)
	tlsChan := make(chan tools.TLSAnalysisResult, 1)
	errChan := make(chan error, 2)

	// Certificate check
	go func() {
		certDetails, err := tools.GetCertDetails(domain, c.timeout)
		if err != nil {
			errChan <- err
			return
		}
		certChan <- certDetails
	}()

	// TLS analysis
	go func() {
		result := tools.AnalyzeTLS(ctx, domain, c.timeout)
		tlsChan <- result
	}()

	timer := time.NewTimer(c.timeout)
	defer timer.Stop()

	var certDetails tools.CertInfo
	var tlsResult tools.TLSAnalysisResult
	errors := []error{}

	// Wait for both checks to complete
	for range 2 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
			return nil, fmt.Errorf("certificate scan timeout")
		case cert := <-certChan:
			certDetails = cert
		case tls := <-tlsChan:
			tlsResult = tls
		case err := <-errChan:
			errors = append(errors, err)
		}
	}

	// Set certificate details
	certData.Issuer = certDetails.Issuer
	certData.CommonName = certDetails.CommonName
	certData.ExpiresAt = certDetails.ExpiresAt
	certData.ExpiresInDays = certDetails.ExpiresInDays
	certData.Status = certDetails.Status
	certData.IsWildcard = certDetails.IsWildcard
	certData.IsSelfSigned = certDetails.IsSelfSigned

	// Set TLS analysis results
	certData.TLSVersions = tlsResult.TLSVersions
	certData.WeakTLSVersions = tlsResult.WeakTLSVersions
	certData.CipherSuites = tlsResult.CipherSuites
	certData.WeakCipherSuites = tlsResult.WeakCipherSuites

	// Return error if certificate fetch failed
	if len(errors) > 0 && certDetails.Issuer == "" {
		return certData, fmt.Errorf("certificate retrieval failed: %v", errors)
	}

	return certData, nil
}
