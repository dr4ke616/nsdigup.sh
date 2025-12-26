package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"checks/internal/logger"
	"checks/pkg/models"
)

type CertificateScanner struct{}

func NewCertificateScanner() *CertificateScanner {
	return &CertificateScanner{}
}

func (c *CertificateScanner) ScanCertificates(ctx context.Context, domain string) (*models.Certificates, error) {
	certData := &models.Certificates{
		History: []models.CertDetails{},
	}

	// Channel for parallel checks
	certChan := make(chan models.CertDetails, 1)
	tlsChan := make(chan TLSAnalysisResult, 1)
	errChan := make(chan error, 2)

	// Certificate check
	go func() {
		dialer := &net.Dialer{
			Timeout: 5 * time.Second,
		}

		conn, err := tls.DialWithDialer(dialer, "tcp", fmt.Sprintf("%s:443", domain), &tls.Config{
			ServerName: domain,
		})
		if err != nil {
			errChan <- fmt.Errorf("TLS connection failed: %w", err)
			return
		}
		defer conn.Close()

		state := conn.ConnectionState()
		if len(state.PeerCertificates) == 0 {
			errChan <- fmt.Errorf("no certificates found")
			return
		}

		cert := state.PeerCertificates[0]

		issuer := cert.Issuer.CommonName
		if issuer == "" && cert.Issuer.Organization != nil && len(cert.Issuer.Organization) > 0 {
			issuer = cert.Issuer.Organization[0]
		}

		status := "Active"
		if time.Now().After(cert.NotAfter) {
			status = "Expired"
		} else if time.Now().Add(30 * 24 * time.Hour).After(cert.NotAfter) {
			status = "Expiring Soon"
			daysRemaining := int(time.Until(cert.NotAfter).Hours() / 24)
			logger.Get().Debug("certificate expiring soon",
				slog.String("domain", domain),
				slog.String("common_name", cert.Subject.CommonName),
				slog.Int("days_remaining", daysRemaining),
				slog.Time("expires", cert.NotAfter))
		}

		isWildcard := false
		if strings.HasPrefix(cert.Subject.CommonName, "*.") {
			isWildcard = true
		}
		for _, san := range cert.DNSNames {
			if strings.HasPrefix(san, "*.") {
				isWildcard = true
				break
			}
		}

		certChan <- models.CertDetails{
			Issuer:     issuer,
			CommonName: cert.Subject.CommonName,
			NotAfter:   cert.NotAfter,
			Status:     status,
			IsWildcard: isWildcard,
		}
	}()

	// TLS analysis
	go func() {
		result := AnalyzeTLS(ctx, domain)
		tlsChan <- result
	}()

	timeout := time.NewTimer(10 * time.Second)
	defer timeout.Stop()

	var certDetails models.CertDetails
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
	certData.Current = certDetails

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
