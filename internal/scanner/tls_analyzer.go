package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

// TLSAnalysisResult contains the results of TLS protocol and cipher analysis
type TLSAnalysisResult struct {
	TLSVersions      []string
	WeakTLSVersions  []string
	CipherSuites     []string
	WeakCipherSuites []string
	Error            error
}

// Weak TLS versions (SSLv3, TLS 1.0, TLS 1.1)
var weakTLSVersions = map[uint16]string{
	tls.VersionSSL30: "SSLv3",
	tls.VersionTLS10: "TLS 1.0",
	tls.VersionTLS11: "TLS 1.1",
}

// Strong TLS versions
var strongTLSVersions = map[uint16]string{
	tls.VersionTLS12: "TLS 1.2",
	tls.VersionTLS13: "TLS 1.3",
}

// Weak cipher patterns (based on OWASP recommendations)
// We check cipher names for these weak patterns
var weakCipherPatterns = []string{
	"RC4",           // RC4 cipher is weak
	"DES_CBC",       // DES and 3DES are weak
	"3DES",          // 3DES is considered weak
	"MD5",           // MD5 hash is weak
	"anon",          // Anonymous DH has no authentication
	"EXPORT",        // Export ciphers are intentionally weak
	"NULL",          // NULL encryption
	"TLS_RSA_WITH_", // RSA key exchange doesn't provide forward secrecy (for informational purposes)
}

// AnalyzeTLS performs comprehensive TLS protocol and cipher suite analysis
func AnalyzeTLS(ctx context.Context, domain string, timeout time.Duration) TLSAnalysisResult {
	result := TLSAnalysisResult{
		TLSVersions:      []string{},
		WeakTLSVersions:  []string{},
		CipherSuites:     []string{},
		WeakCipherSuites: []string{},
	}

	// Ensure domain has port
	target := domain
	if _, _, err := net.SplitHostPort(domain); err != nil {
		target = net.JoinHostPort(domain, "443")
	}

	// Test each TLS version
	versionsToTest := []uint16{
		tls.VersionTLS10,
		tls.VersionTLS11,
		tls.VersionTLS12,
		tls.VersionTLS13,
	}

	supportedVersions := make(map[uint16]bool)
	var allCipherSuites []uint16
	cipherSuiteNames := make(map[uint16]string)

	for _, version := range versionsToTest {
		// Test if this version is supported
		config := &tls.Config{
			MinVersion:         version,
			MaxVersion:         version,
			InsecureSkipVerify: true, // We're testing support, not validating certs
		}

		dialer := &net.Dialer{
			Timeout: timeout,
		}

		conn, err := tls.DialWithDialer(dialer, "tcp", target, config)
		if err != nil {
			// This version not supported or connection failed
			continue
		}

		state := conn.ConnectionState()
		supportedVersions[version] = true

		// Record cipher suite if not already seen
		cipherID := state.CipherSuite
		if _, exists := cipherSuiteNames[cipherID]; !exists {
			allCipherSuites = append(allCipherSuites, cipherID)
			cipherSuiteNames[cipherID] = tls.CipherSuiteName(cipherID)
		}

		conn.Close()
	}

	// If no versions worked, return error
	if len(supportedVersions) == 0 {
		result.Error = fmt.Errorf("unable to establish TLS connection")
		return result
	}

	// Categorize TLS versions
	for version := range supportedVersions {
		versionName := getTLSVersionName(version)
		result.TLSVersions = append(result.TLSVersions, versionName)

		if _, isWeak := weakTLSVersions[version]; isWeak {
			result.WeakTLSVersions = append(result.WeakTLSVersions, versionName)
		}
	}

	// Enumerate cipher suites more thoroughly using TLS 1.2
	// (TLS 1.3 has a fixed set of cipher suites)
	if supportedVersions[tls.VersionTLS12] {
		detectedCiphers := probeCipherSuites(target, timeout)
		for _, cipher := range detectedCiphers {
			if _, exists := cipherSuiteNames[cipher]; !exists {
				allCipherSuites = append(allCipherSuites, cipher)
				cipherSuiteNames[cipher] = tls.CipherSuiteName(cipher)
			}
		}
	}

	// Categorize cipher suites
	for _, cipherID := range allCipherSuites {
		cipherName := cipherSuiteNames[cipherID]
		result.CipherSuites = append(result.CipherSuites, cipherName)

		if isWeakCipher(cipherName) {
			result.WeakCipherSuites = append(result.WeakCipherSuites, cipherName)
		}
	}

	return result
}

// probeCipherSuites attempts to detect supported cipher suites
func probeCipherSuites(target string, timeout time.Duration) []uint16 {
	var detected []uint16

	// Test with default cipher suites first
	config := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
	}

	dialer := &net.Dialer{
		Timeout: timeout,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", target, config)
	if err != nil {
		return detected
	}

	state := conn.ConnectionState()
	detected = append(detected, state.CipherSuite)
	conn.Close()

	return detected
}

// getTLSVersionName returns a human-readable TLS version name
func getTLSVersionName(version uint16) string {
	if name, ok := weakTLSVersions[version]; ok {
		return name
	}
	if name, ok := strongTLSVersions[version]; ok {
		return name
	}
	return fmt.Sprintf("Unknown (0x%04x)", version)
}

// isWeakCipher checks if a cipher suite name contains weak patterns
func isWeakCipher(cipherName string) bool {
	for _, pattern := range weakCipherPatterns {
		if strings.Contains(cipherName, pattern) {
			return true
		}
	}
	return false
}
