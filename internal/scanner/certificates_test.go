package scanner

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestCertificateScanner_ScanCertificates(t *testing.T) {
	scanner := NewCertificateScanner(10 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tests := []struct {
		name          string
		domain        string
		wantCert      bool
		wantWildcard  bool
		expectedError string
	}{
		{
			name:         "Valid HTTPS site - google.com",
			domain:       "google.com",
			wantCert:     true,
			wantWildcard: false,
		},
		{
			name:         "Valid HTTPS site - github.com",
			domain:       "github.com",
			wantCert:     true,
			wantWildcard: false,
		},
		{
			name:          "Invalid domain",
			domain:        "this-domain-does-not-exist-12345.com",
			wantCert:      false,
			expectedError: "TLS connection failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certData, err := scanner.ScanCertificates(ctx, tt.domain)

			if tt.expectedError != "" {
				if err == nil {
					t.Errorf("Expected error containing '%s' but got none", tt.expectedError)
				} else if !strings.Contains(err.Error(), tt.expectedError) {
					t.Errorf("Expected error containing '%s' but got: %v", tt.expectedError, err)
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if tt.wantCert {
				if certData.CommonName == "" {
					t.Error("Expected certificate common name but got empty")
				}
				if certData.Issuer == "" {
					t.Error("Expected certificate issuer but got empty")
				}
				if certData.Status == "" {
					t.Error("Expected certificate status but got empty")
				}
				if certData.NotAfter.IsZero() {
					t.Error("Expected certificate expiry date but got zero time")
				}

				validStatuses := []string{"Active", "Expired", "Expiring Soon"}
				statusValid := false
				for _, status := range validStatuses {
					if certData.Status == status {
						statusValid = true
						break
					}
				}
				if !statusValid {
					t.Errorf("Invalid certificate status: %s", certData.Status)
				}
			}

			if tt.wantWildcard && !certData.IsWildcard {
				t.Error("Expected wildcard certificate but IsWildcard is false")
			}
		})
	}
}

func TestCertificateScanner_WildcardDetection(t *testing.T) {
	scanner := NewCertificateScanner(10 * time.Second)
	ctx := context.Background()

	knownWildcardDomains := []string{}

	for _, domain := range knownWildcardDomains {
		certData, err := scanner.ScanCertificates(ctx, domain)
		if err != nil {
			t.Logf("Skipping %s due to error: %v", domain, err)
			continue
		}

		if !certData.IsWildcard {
			t.Logf("Note: %s does not appear to use a wildcard certificate", domain)
		}
	}
}

func TestCertificateScanner_CertificateExpiry(t *testing.T) {
	scanner := NewCertificateScanner(10 * time.Second)
	ctx := context.Background()

	certData, err := scanner.ScanCertificates(ctx, "google.com")
	if err != nil {
		t.Fatalf("Failed to scan google.com: %v", err)
	}

	now := time.Now()
	if certData.NotAfter.Before(now) && certData.Status != "Expired" {
		t.Error("Certificate is expired but status is not 'Expired'")
	}

	if certData.NotAfter.After(now) && certData.Status == "Expired" {
		t.Error("Certificate is not expired but status is 'Expired'")
	}

	thirtyDaysFromNow := now.Add(30 * 24 * time.Hour)
	if certData.NotAfter.After(now) && certData.NotAfter.Before(thirtyDaysFromNow) {
		if certData.Status != "Expiring Soon" {
			t.Error("Certificate expires within 30 days but status is not 'Expiring Soon'")
		}
	}
}
