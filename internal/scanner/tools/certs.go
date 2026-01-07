package tools

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/ocsp"

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
	IsValidHostname bool
	IsIPAddress     bool
	IsUntrustedRoot bool
	IsRevoked       bool
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
	isValidHostname := validateHostname(domain, cert)

	// Extract Subject Alternative Names
	subjectAltNames := make([]string, len(cert.DNSNames))
	copy(subjectAltNames, cert.DNSNames)

	// Verify certificate chain against system roots
	isUntrustedRoot := false
	opts := x509.VerifyOptions{
		DNSName:       domain,
		Intermediates: x509.NewCertPool(),
	}
	// Add intermediate certificates to the pool
	for _, intermediateCert := range state.PeerCertificates[1:] {
		opts.Intermediates.AddCert(intermediateCert)
	}
	// Try to verify against system roots
	if _, err := cert.Verify(opts); err != nil {
		isUntrustedRoot = true
		logger.Get().Debug("certificate chain verification failed",
			slog.String("domain", domain),
			slog.String("common_name", cert.Subject.CommonName),
			slog.String("error", err.Error()))
	}

	// Check certificate revocation status via OCSP
	isRevoked := false
	if len(state.PeerCertificates) > 1 {
		// We need the issuer certificate to create OCSP request
		issuerCert := state.PeerCertificates[1]
		isRevoked = checkOCSPRevocation(cert, issuerCert, timeout)
	} else {
		logger.Get().Debug("no issuer certificate available for OCSP check",
			slog.String("domain", domain))
	}

	// Log hostname mismatch for debugging
	if !isValidHostname {
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
		IsValidHostname: isValidHostname,
		IsIPAddress:     isIP,
		IsUntrustedRoot: isUntrustedRoot,
		IsRevoked:       isRevoked,
	}, nil
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

// checkOCSPRevocation checks if a certificate has been revoked using OCSP.
// It returns true if the certificate is revoked, false otherwise.
// Errors during OCSP checking are logged but not treated as revocation.
func checkOCSPRevocation(cert, issuer *x509.Certificate, timeout time.Duration) bool {
	// Check if certificate has OCSP server URLs
	if len(cert.OCSPServer) == 0 {
		logger.Get().Debug("no OCSP servers found in certificate")
		return false
	}

	// Create OCSP request
	ocspRequest, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		logger.Get().Debug("failed to create OCSP request",
			slog.String("error", err.Error()))
		return false
	}

	// Try each OCSP server
	for _, server := range cert.OCSPServer {
		httpClient := &http.Client{
			Timeout: timeout,
		}

		httpRequest, err := http.NewRequest("POST", server, bytes.NewReader(ocspRequest))
		if err != nil {
			logger.Get().Debug("failed to create OCSP HTTP request",
				slog.String("server", server),
				slog.String("error", err.Error()))
			continue
		}

		httpRequest.Header.Set("Content-Type", "application/ocsp-request")
		httpRequest.Header.Set("Accept", "application/ocsp-response")

		httpResponse, err := httpClient.Do(httpRequest)
		if err != nil {
			logger.Get().Debug("OCSP request failed",
				slog.String("server", server),
				slog.String("error", err.Error()))
			continue
		}
		defer httpResponse.Body.Close()

		body, err := io.ReadAll(httpResponse.Body)
		if err != nil {
			logger.Get().Debug("failed to read OCSP response",
				slog.String("server", server),
				slog.String("error", err.Error()))
			continue
		}

		ocspResponse, err := ocsp.ParseResponse(body, issuer)
		if err != nil {
			logger.Get().Debug("failed to parse OCSP response",
				slog.String("server", server),
				slog.String("error", err.Error()))
			continue
		}

		// Check the response status
		switch ocspResponse.Status {
		case ocsp.Good:
			logger.Get().Debug("OCSP: certificate is good",
				slog.String("server", server))
			return false
		case ocsp.Revoked:
			logger.Get().Debug("OCSP: certificate is revoked",
				slog.String("server", server),
				slog.Time("revoked_at", ocspResponse.RevokedAt))
			return true
		case ocsp.Unknown:
			logger.Get().Debug("OCSP: certificate status unknown",
				slog.String("server", server))
			continue
		}
	}

	// If we couldn't get a definitive answer, assume not revoked
	return false
}
