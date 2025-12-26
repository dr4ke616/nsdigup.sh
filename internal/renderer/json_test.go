package renderer

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"checks/pkg/models"
)

func TestJSONRenderer_Render(t *testing.T) {
	renderer := NewJSONRenderer()

	report := &models.Report{
		Target:    "example.com",
		Timestamp: time.Date(2023, 12, 25, 10, 30, 0, 0, time.UTC),
		Identity: models.Identity{
			IP:          "192.168.1.1",
			Nameservers: []string{"ns1.example.com", "ns2.example.com"},
			Registrar:   "Example Registrar",
		},
		Certificates: models.Certificates{
			Current: models.CertDetails{
				Issuer:     "Let's Encrypt",
				CommonName: "example.com",
				Status:     "Active",
				IsWildcard: false,
			},
		},
		Misconfigurations: models.Misconfigurations{
			EmailSec: models.EmailSec{
				SPF:   "v=spf1 ~all",
				DMARC: "quarantine",
			},
			Headers: []string{"Missing HSTS header"},
		},
	}

	var buf bytes.Buffer
	err := renderer.Render(&buf, report)

	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	// Verify it's valid JSON by unmarshaling
	var decoded models.Report
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Errorf("Generated invalid JSON: %v", err)
	}

	// Verify content
	if decoded.Target != "example.com" {
		t.Errorf("Expected target 'example.com', got '%s'", decoded.Target)
	}

	if decoded.Identity.IP != "192.168.1.1" {
		t.Errorf("Expected IP '192.168.1.1', got '%s'", decoded.Identity.IP)
	}

	if len(decoded.Identity.Nameservers) != 2 {
		t.Errorf("Expected 2 nameservers, got %d", len(decoded.Identity.Nameservers))
	}

	if decoded.Certificates.Current.Issuer != "Let's Encrypt" {
		t.Errorf("Expected issuer 'Let's Encrypt', got '%s'", decoded.Certificates.Current.Issuer)
	}

	if decoded.Misconfigurations.EmailSec.DMARC != "quarantine" {
		t.Errorf("Expected DMARC 'quarantine', got '%s'", decoded.Misconfigurations.EmailSec.DMARC)
	}

	if len(decoded.Misconfigurations.Headers) != 1 {
		t.Errorf("Expected 1 header issue, got %d", len(decoded.Misconfigurations.Headers))
	}
}

func TestJSONRenderer_CompactMode(t *testing.T) {
	compactRenderer := NewJSONRendererCompact()
	indentedRenderer := NewJSONRenderer()

	report := &models.Report{
		Target: "test.com",
		Identity: models.Identity{
			IP: "1.2.3.4",
		},
	}

	// Render compact
	var compactBuf bytes.Buffer
	err := compactRenderer.Render(&compactBuf, report)
	if err != nil {
		t.Errorf("Compact render error: %v", err)
	}

	// Render indented
	var indentedBuf bytes.Buffer
	err = indentedRenderer.Render(&indentedBuf, report)
	if err != nil {
		t.Errorf("Indented render error: %v", err)
	}

	compactOutput := compactBuf.String()
	indentedOutput := indentedBuf.String()

	// Compact should be shorter (no indentation/newlines)
	if len(compactOutput) >= len(indentedOutput) {
		t.Error("Expected compact output to be shorter than indented")
	}

	// Compact should not contain indentation spaces
	if strings.Contains(compactOutput, "  \"") {
		t.Error("Compact output should not contain indentation")
	}

	// Indented should contain indentation
	if !strings.Contains(indentedOutput, "  \"") {
		t.Error("Indented output should contain indentation")
	}

	// Both should be valid JSON with same content
	var compactData, indentedData models.Report

	if err := json.Unmarshal(compactBuf.Bytes(), &compactData); err != nil {
		t.Errorf("Compact JSON invalid: %v", err)
	}

	if err := json.Unmarshal(indentedBuf.Bytes(), &indentedData); err != nil {
		t.Errorf("Indented JSON invalid: %v", err)
	}

	if compactData.Target != indentedData.Target {
		t.Error("Compact and indented should have same target")
	}

	if compactData.Identity.IP != indentedData.Identity.IP {
		t.Error("Compact and indented should have same IP")
	}
}

func TestJSONRenderer_EmptyReport(t *testing.T) {
	renderer := NewJSONRenderer()

	report := &models.Report{
		Target:    "empty.com",
		Timestamp: time.Now(),
		Identity:  models.Identity{},
		Certificates: models.Certificates{
			Current: models.CertDetails{},
			History: []models.CertDetails{},
		},
		Misconfigurations: models.Misconfigurations{
			DNSGlue: []string{},
			Headers: []string{},
		},
	}

	var buf bytes.Buffer
	err := renderer.Render(&buf, report)

	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	// Should still be valid JSON
	var decoded models.Report
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Errorf("Generated invalid JSON: %v", err)
	}

	// Check zero/empty values are preserved
	if decoded.Target != "empty.com" {
		t.Error("Target should be preserved")
	}

	if decoded.Identity.IP != "" {
		t.Error("Empty IP should remain empty")
	}

	if len(decoded.Identity.Nameservers) != 0 {
		t.Error("Empty nameservers should be empty slice")
	}

	if decoded.Certificates.Current.CommonName != "" {
		t.Error("Empty common name should remain empty")
	}
}

func TestJSONRenderer_NilReport(t *testing.T) {
	renderer := NewJSONRenderer()

	var buf bytes.Buffer
	err := renderer.Render(&buf, nil)

	if err != nil {
		t.Errorf("Expected no error for nil report, got: %v", err)
	}

	// Should output error JSON
	var result map[string]string
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Errorf("Error JSON should be valid: %v", err)
	}

	if result["error"] != "report cannot be nil" {
		t.Errorf("Expected error message, got: %v", result)
	}
}

func TestJSONRenderer_ComplexStructures(t *testing.T) {
	renderer := NewJSONRenderer()

	report := &models.Report{
		Target: "complex.com",
		Identity: models.Identity{
			Nameservers: []string{"ns1.complex.com", "ns2.complex.com", "ns3.complex.com"},
		},
		Certificates: models.Certificates{
			History: []models.CertDetails{
				{
					Issuer:     "Old CA",
					CommonName: "old.complex.com",
					Status:     "Expired",
				},
				{
					Issuer:     "Previous CA",
					CommonName: "*.complex.com",
					IsWildcard: true,
				},
			},
		},
		Misconfigurations: models.Misconfigurations{
			DNSGlue: []string{"dangling CNAME", "orphaned A record"},
			Headers: []string{
				"Missing HSTS header",
				"Missing CSP header",
				"Missing X-Frame-Options header",
			},
		},
	}

	var buf bytes.Buffer
	err := renderer.Render(&buf, report)

	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	var decoded models.Report
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Errorf("Generated invalid JSON: %v", err)
	}

	// Verify arrays are preserved
	if len(decoded.Identity.Nameservers) != 3 {
		t.Errorf("Expected 3 nameservers, got %d", len(decoded.Identity.Nameservers))
	}

	if len(decoded.Certificates.History) != 2 {
		t.Errorf("Expected 2 historical certificates, got %d", len(decoded.Certificates.History))
	}

	if len(decoded.Misconfigurations.Headers) != 3 {
		t.Errorf("Expected 3 header issues, got %d", len(decoded.Misconfigurations.Headers))
	}

	if len(decoded.Misconfigurations.DNSGlue) != 2 {
		t.Errorf("Expected 2 DNS glue issues, got %d", len(decoded.Misconfigurations.DNSGlue))
	}

	// Verify nested boolean values
	if !decoded.Certificates.History[1].IsWildcard {
		t.Error("Expected second historical cert to be wildcard")
	}
}

func TestJSONRenderer_SpecialCharacters(t *testing.T) {
	renderer := NewJSONRenderer()

	report := &models.Report{
		Target: "special.com",
		Identity: models.Identity{
			Owner: "Test Corp \"Special Edition\"", // Contains quotes
		},
		Misconfigurations: models.Misconfigurations{
			EmailSec: models.EmailSec{
				SPF: "v=spf1 include:_spf.example.com ~all", // Contains special chars
			},
			Headers: []string{
				"Content-Security-Policy: default-src 'self'", // Contains quotes and special chars
			},
		},
	}

	var buf bytes.Buffer
	err := renderer.Render(&buf, report)

	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	// Should handle special characters properly in JSON
	var decoded models.Report
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Errorf("JSON with special characters should be valid: %v", err)
	}

	// Verify special characters are preserved
	expectedOwner := "Test Corp \"Special Edition\""
	if decoded.Identity.Owner != expectedOwner {
		t.Errorf("Expected owner '%s', got '%s'", expectedOwner, decoded.Identity.Owner)
	}

	expectedSPF := "v=spf1 include:_spf.example.com ~all"
	if decoded.Misconfigurations.EmailSec.SPF != expectedSPF {
		t.Errorf("Expected SPF '%s', got '%s'", expectedSPF, decoded.Misconfigurations.EmailSec.SPF)
	}
}
