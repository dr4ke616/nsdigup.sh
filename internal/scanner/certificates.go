package scanner

import (
	"context"
	"fmt"
	"time"

	"checks/pkg/models"
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
	certChan := make(chan CertInfo, 1)
	tlsChan := make(chan TLSAnalysisResult, 1)
	errChan := make(chan error, 2)

	// Certificate check
	go func() {
		certDetails, err := GetCertDetails(domain, c.timeout)
		if err != nil {
			errChan <- err
			return
		}
		certChan <- certDetails
	}()

	// TLS analysis
	go func() {
		result := AnalyzeTLS(ctx, domain, c.timeout)
		tlsChan <- result
	}()

	timeout := time.NewTimer(c.timeout)
	defer timeout.Stop()

	var certDetails CertInfo
	var tlsResult TLSAnalysisResult
	errors := []error{}

	// Wait for both checks to complete
	for i := 0; i < 2; i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timeout.C:
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
	certData.NotAfter = certDetails.NotAfter
	certData.Status = certDetails.Status
	certData.IsWildcard = certDetails.IsWildcard

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
