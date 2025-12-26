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

	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", fmt.Sprintf("%s:443", domain), &tls.Config{
		ServerName: domain,
	})
	if err != nil {
		return certData, fmt.Errorf("TLS connection failed: %w", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return certData, fmt.Errorf("no certificates found")
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

	certData.Current = models.CertDetails{
		Issuer:     issuer,
		CommonName: cert.Subject.CommonName,
		NotAfter:   cert.NotAfter,
		Status:     status,
		IsWildcard: isWildcard,
	}

	return certData, nil
}
