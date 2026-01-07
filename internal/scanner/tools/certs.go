package tools

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"nsdigup/internal/logger"
)

// CertInfo contains the certificate details extracted from a TLS connection.
type CertInfo struct {
	Issuer          string
	CommonName      string
	ExpiresAt       time.Time
	ExpiresInDays   int
	Status          string
	IsWildcard      bool
	IsSelfSigned    bool
	SubjectAltNames []string
	HostnameMatch   bool
	IsIPAddress     bool
}

// isIPAddress checks if the given domain string is an IP address.
func isIPAddress(domain string) bool {
	return net.ParseIP(domain) != nil
}

// matchHostname handles wildcard matching according to RFC 6125.
func matchHostname(domain, certName string) bool {
	// Exact match
	if domain == certName {
		return true
	}

	// Wildcard matching
	if strings.HasPrefix(certName, "*.") {
		// Extract the base domain from cert name (e.g., "*.example.com" -> "example.com")
		baseCertName := certName[2:] // Remove "*."

		// Check if domain ends with the base cert name
		if !strings.HasSuffix(domain, baseCertName) {
			return false
		}

		// Extract the subdomain part
		// For "www.example.com" with "*.example.com", subdomain is "www"
		subdomainWithDot := domain[:len(domain)-len(baseCertName)]

		// Must have exactly one subdomain level (no dots in subdomain part except the trailing one)
		// "www." is valid, "foo.bar." is not
		if strings.Count(subdomainWithDot, ".") != 1 {
			return false
		}

		// Must not be empty (*.example.com doesn't match example.com)
		if len(subdomainWithDot) <= 1 { // Just the dot
			return false
		}

		return true
	}

	return false
}

// validateHostname checks if the domain matches the certificate's allowed names.
// It handles wildcard certificates according to RFC 6125.
func validateHostname(domain string, cert *x509.Certificate) bool {
	// If connecting via IP, check certificate's IP addresses
	if ip := net.ParseIP(domain); ip != nil {
		for _, certIP := range cert.IPAddresses {
			if ip.Equal(certIP) {
				return true
			}
		}
		return false
	}

	// Normalize domain to lowercase for comparison
	domain = strings.ToLower(domain)

	// Check against all DNS names (SANs)
	for _, name := range cert.DNSNames {
		if matchHostname(domain, strings.ToLower(name)) {
			return true
		}
	}

	// Fallback to CommonName if no SANs (deprecated but still used)
	if len(cert.DNSNames) == 0 && cert.Subject.CommonName != "" {
		return matchHostname(domain, strings.ToLower(cert.Subject.CommonName))
	}

	return false
}

// GetCertDetails retrieves and analyzes the TLS certificate for the given domain.
// It connects to the domain on port 443 and extracts certificate information including
// issuer, common name, expiration, wildcard status, and overall status.
func GetCertDetails(domain string, timeout time.Duration) (CertInfo, error) {
	// Detect if connecting via IP address
	isIP := isIPAddress(domain)

	dialer := &net.Dialer{
		Timeout: timeout,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", fmt.Sprintf("%s:443", domain), &tls.Config{
		ServerName:         domain,
		InsecureSkipVerify: true, // Allow connection to inspect expired certs
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

	// Calculate days until expiration
	expiresInDays := int(time.Until(cert.NotAfter).Hours() / 24)

	status := "Active"
	if time.Now().After(cert.NotAfter) {
		status = "Expired"
	} else if time.Now().Add(30 * 24 * time.Hour).After(cert.NotAfter) {
		status = "Expiring Soon"
		logger.Get().Debug("certificate expiring soon",
			slog.String("domain", domain),
			slog.String("common_name", cert.Subject.CommonName),
			slog.Int("days_remaining", expiresInDays),
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

	// Check if certificate is self-signed
	isSelfSigned := cert.Issuer.String() == cert.Subject.String()

	// Perform hostname validation
	hostnameMatch := validateHostname(domain, cert)

	// Extract Subject Alternative Names
	subjectAltNames := make([]string, len(cert.DNSNames))
	copy(subjectAltNames, cert.DNSNames)

	// Log hostname mismatch for debugging
	if !hostnameMatch {
		logger.Get().Debug("hostname mismatch detected",
			slog.String("domain", domain),
			slog.String("common_name", cert.Subject.CommonName),
			slog.Any("sans", subjectAltNames),
			slog.Bool("is_ip", isIP))
	}

	return CertInfo{
		Issuer:          issuer,
		CommonName:      cert.Subject.CommonName,
		ExpiresAt:       cert.NotAfter,
		ExpiresInDays:   expiresInDays,
		Status:          status,
		IsWildcard:      isWildcard,
		IsSelfSigned:    isSelfSigned,
		SubjectAltNames: subjectAltNames,
		HostnameMatch:   hostnameMatch,
		IsIPAddress:     isIP,
	}, nil
}
