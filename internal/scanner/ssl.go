package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"checks/pkg/models"
)

type SSLScanner struct{}

func NewSSLScanner() *SSLScanner {
	return &SSLScanner{}
}

func (s *SSLScanner) ScanCertificates(ctx context.Context, domain string) (*models.CertData, error) {
	certData := &models.CertData{
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
	} else if time.Now().Add(30*24*time.Hour).After(cert.NotAfter) {
		status = "Expiring Soon"
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