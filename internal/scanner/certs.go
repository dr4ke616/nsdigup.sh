package scanner

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"checks/internal/logger"
)

// CertInfo contains the certificate details extracted from a TLS connection.
type CertInfo struct {
	Issuer     string
	CommonName string
	NotAfter   time.Time
	Status     string
	IsWildcard bool
}

// GetCertDetails retrieves and analyzes the TLS certificate for the given domain.
// It connects to the domain on port 443 and extracts certificate information including
// issuer, common name, expiration, wildcard status, and overall status.
func GetCertDetails(domain string) (CertInfo, error) {
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", fmt.Sprintf("%s:443", domain), &tls.Config{
		ServerName: domain,
	})
	if err != nil {
		return CertInfo{}, fmt.Errorf("TLS connection failed: %w", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return CertInfo{}, fmt.Errorf("no certificates found")
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

	return CertInfo{
		Issuer:     issuer,
		CommonName: cert.Subject.CommonName,
		NotAfter:   cert.NotAfter,
		Status:     status,
		IsWildcard: isWildcard,
	}, nil
}
