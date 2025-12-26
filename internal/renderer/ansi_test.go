package renderer

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"checks/pkg/models"
)

func TestANSIRenderer_Render(t *testing.T) {
	renderer := NewANSIRenderer()

	report := &models.Report{
		Target:    "example.com",
		Timestamp: time.Date(2023, 12, 25, 10, 30, 0, 0, time.UTC),
		Identity: models.Identity{
			IP:          "192.168.1.1",
			Nameservers: []string{"ns1.example.com", "ns2.example.com"},
			Registrar:   "Example Registrar",
			Owner:       "Example Corp",
			ExpiresDays: 45,
		},
		Certificates: models.CertData{
			Current: models.CertDetails{
				Issuer:     "Let's Encrypt",
				CommonName: "example.com",
				NotAfter:   time.Date(2024, 3, 15, 0, 0, 0, 0, time.UTC),
				Status:     "Active",
				IsWildcard: false,
			},
		},
		Misconfigurations: models.Misconfigurations{
			EmailSec: models.EmailSec{
				SPF:    "v=spf1 include:_spf.google.com ~all",
				DMARC:  "reject",
				IsWeak: false,
			},
			Headers: []string{"Missing HSTS header", "Missing CSP header"},
		},
	}

	var buf bytes.Buffer
	err := renderer.Render(&buf, report)

	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	output := buf.String()

	// Check for main sections
	if !strings.Contains(output, "checks.sh") {
		t.Error("Expected header to contain 'checks.sh'")
	}

	if !strings.Contains(output, "[ IDENTITY ]") {
		t.Error("Expected IDENTITY section")
	}

	if !strings.Contains(output, "[ CERTIFICATES ]") {
		t.Error("Expected CERTIFICATES section")
	}

	if !strings.Contains(output, "[ MISCONFIGURATIONS ]") {
		t.Error("Expected MISCONFIGURATIONS section")
	}

	// Check content
	if !strings.Contains(output, "example.com") {
		t.Error("Expected target domain")
	}

	if !strings.Contains(output, "192.168.1.1") {
		t.Error("Expected IP address")
	}

	if !strings.Contains(output, "ns1.example.com") {
		t.Error("Expected nameserver")
	}

	if !strings.Contains(output, "Let's Encrypt") {
		t.Error("Expected certificate issuer")
	}

	if !strings.Contains(output, "Missing HSTS header") {
		t.Error("Expected header issue")
	}
}

func TestANSIRenderer_EmptyFields(t *testing.T) {
	renderer := NewANSIRenderer()

	// Report with minimal data (simulating MVP phase)
	report := &models.Report{
		Target:    "minimal.com",
		Timestamp: time.Now(),
		Identity: models.Identity{
			IP: "1.2.3.4",
			// No registrar, owner, expires - should be hidden
		},
		Certificates: models.CertData{
			// No current certificate
		},
		Misconfigurations: models.Misconfigurations{
			// No issues
		},
	}

	var buf bytes.Buffer
	err := renderer.Render(&buf, report)

	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	output := buf.String()

	// Should contain IP
	if !strings.Contains(output, "1.2.3.4") {
		t.Error("Expected IP address")
	}

	// Should NOT contain empty fields
	if strings.Contains(output, "Registrar:") {
		t.Error("Expected no registrar field when empty")
	}

	if strings.Contains(output, "Owner:") {
		t.Error("Expected no owner field when empty")
	}

	if strings.Contains(output, "Expires:") {
		t.Error("Expected no expires field when zero")
	}

	// Should show no certificate info message
	if !strings.Contains(output, "No certificate information available") {
		t.Error("Expected no certificate message")
	}

	// Should show no misconfigurations message
	if !strings.Contains(output, "No misconfigurations detected") {
		t.Error("Expected no misconfigurations message")
	}
}

func TestANSIRenderer_WildcardCertificate(t *testing.T) {
	renderer := NewANSIRenderer()

	report := &models.Report{
		Target:    "wildcard.com",
		Timestamp: time.Now(),
		Certificates: models.CertData{
			Current: models.CertDetails{
				CommonName: "*.wildcard.com",
				IsWildcard: true,
				Status:     "Active",
			},
		},
	}

	var buf bytes.Buffer
	err := renderer.Render(&buf, report)

	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	output := buf.String()

	if !strings.Contains(output, "*.wildcard.com") {
		t.Error("Expected wildcard domain name")
	}

	if !strings.Contains(output, "(wildcard)") {
		t.Error("Expected wildcard indicator")
	}
}

func TestANSIRenderer_ExpiredCertificate(t *testing.T) {
	renderer := NewANSIRenderer()

	yesterday := time.Now().Add(-24 * time.Hour)

	report := &models.Report{
		Target:    "expired.com",
		Timestamp: time.Now(),
		Certificates: models.CertData{
			Current: models.CertDetails{
				CommonName: "expired.com",
				NotAfter:   yesterday,
				Status:     "Expired",
			},
		},
	}

	var buf bytes.Buffer
	err := renderer.Render(&buf, report)

	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	output := buf.String()

	if !strings.Contains(output, "Expired") {
		t.Error("Expected expired status")
	}

	// Should contain negative days until expiry
	if !strings.Contains(output, "(-1 days)") && !strings.Contains(output, "(-") {
		t.Error("Expected negative days for expired certificate")
	}
}

func TestANSIRenderer_WeakEmailSecurity(t *testing.T) {
	renderer := NewANSIRenderer()

	report := &models.Report{
		Target:    "weak.com",
		Timestamp: time.Now(),
		Misconfigurations: models.Misconfigurations{
			EmailSec: models.EmailSec{
				SPF:    "v=spf1 +all", // Weak SPF
				DMARC:  "none",        // Weak DMARC
				IsWeak: true,
			},
		},
	}

	var buf bytes.Buffer
	err := renderer.Render(&buf, report)

	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	output := buf.String()

	if !strings.Contains(output, "v=spf1 +all") {
		t.Error("Expected weak SPF record")
	}

	if !strings.Contains(output, "none") {
		t.Error("Expected weak DMARC policy")
	}

	if !strings.Contains(output, "Weak email security") {
		t.Error("Expected weak security warning")
	}
}

func TestANSIRenderer_NilReport(t *testing.T) {
	renderer := NewANSIRenderer()

	var buf bytes.Buffer
	err := renderer.Render(&buf, nil)

	if err == nil {
		t.Error("Expected error for nil report")
	}

	if !strings.Contains(err.Error(), "cannot be nil") {
		t.Errorf("Expected nil error message, got: %v", err)
	}
}
