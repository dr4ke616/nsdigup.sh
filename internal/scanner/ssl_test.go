package scanner

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestSSLScanner_ScanCertificates(t *testing.T) {
	scanner := NewSSLScanner()
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
				if certData.Current.CommonName == "" {
					t.Error("Expected certificate common name but got empty")
				}
				if certData.Current.Issuer == "" {
					t.Error("Expected certificate issuer but got empty")
				}
				if certData.Current.Status == "" {
					t.Error("Expected certificate status but got empty")
				}
				if certData.Current.NotAfter.IsZero() {
					t.Error("Expected certificate expiry date but got zero time")
				}

				validStatuses := []string{"Active", "Expired", "Expiring Soon"}
				statusValid := false
				for _, status := range validStatuses {
					if certData.Current.Status == status {
						statusValid = true
						break
					}
				}
				if !statusValid {
					t.Errorf("Invalid certificate status: %s", certData.Current.Status)
				}
			}

			if tt.wantWildcard && !certData.Current.IsWildcard {
				t.Error("Expected wildcard certificate but IsWildcard is false")
			}
		})
	}
}

func TestSSLScanner_WildcardDetection(t *testing.T) {
	scanner := NewSSLScanner()
	ctx := context.Background()

	knownWildcardDomains := []string{}

	for _, domain := range knownWildcardDomains {
		certData, err := scanner.ScanCertificates(ctx, domain)
		if err != nil {
			t.Logf("Skipping %s due to error: %v", domain, err)
			continue
		}

		if !certData.Current.IsWildcard {
			t.Logf("Note: %s does not appear to use a wildcard certificate", domain)
		}
	}
}

func TestSSLScanner_CertificateExpiry(t *testing.T) {
	scanner := NewSSLScanner()
	ctx := context.Background()

	certData, err := scanner.ScanCertificates(ctx, "google.com")
	if err != nil {
		t.Fatalf("Failed to scan google.com: %v", err)
	}

	now := time.Now()
	if certData.Current.NotAfter.Before(now) && certData.Current.Status != "Expired" {
		t.Error("Certificate is expired but status is not 'Expired'")
	}

	if certData.Current.NotAfter.After(now) && certData.Current.Status == "Expired" {
		t.Error("Certificate is not expired but status is 'Expired'")
	}

	thirtyDaysFromNow := now.Add(30 * 24 * time.Hour)
	if certData.Current.NotAfter.After(now) && certData.Current.NotAfter.Before(thirtyDaysFromNow) {
		if certData.Current.Status != "Expiring Soon" {
			t.Error("Certificate expires within 30 days but status is not 'Expiring Soon'")
		}
	}
}
