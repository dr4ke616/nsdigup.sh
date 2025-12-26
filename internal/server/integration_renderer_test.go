package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"nsdigup/internal/config"
	"nsdigup/pkg/models"
)

func TestHandler_JSONFormat(t *testing.T) {
	mockReport := &models.Report{
		Target:   "json-test.com",
		Identity: models.Identity{IP: "1.2.3.4"},
	}
	mock := &mockScanner{report: mockReport}

	cfg := &config.Config{
		App:   config.AppConfig{Host: "0.0.0.0", Port: 8080, AdvertisedAddress: "http://localhost:8080"},
		Cache: config.CacheConfig{Mode: config.CacheModeMem, TTL: 1 * time.Hour},
	}
	handler := NewHandler(cfg)
	handler.scanner = mock

	// Test explicit JSON format via Accept header
	req := httptest.NewRequest("GET", "/json-test.com", nil)
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	contentType := w.Header().Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		t.Errorf("Expected JSON content type, got %s", contentType)
	}

	body := w.Body.String()
	if !strings.Contains(body, `"target": "json-test.com"`) {
		t.Error("Expected JSON formatted response")
	}

	if !strings.Contains(body, `"ip_address": "1.2.3.4"`) {
		t.Error("Expected IP in JSON response")
	}
}

func TestHandler_ANSIFormat(t *testing.T) {
	mockReport := &models.Report{
		Target: "ansi-test.com",
		Identity: models.Identity{
			IP:          "5.6.7.8",
			Nameservers: []string{"ns1.test.com", "ns2.test.com"},
		},
		Certificates: models.Certificates{
			CommonName: "ansi-test.com",
			Issuer:     "Test CA",
			Status:     "Active",
			IsWildcard: false,
		},
		Findings: models.Findings{
			EmailSec: models.EmailSec{
				SPF:    "v=spf1 ~all",
				DMARC:  "quarantine",
				IsWeak: false,
			},
			Headers: []string{"Missing HSTS header"},
		},
	}
	mock := &mockScanner{report: mockReport}

	cfg := &config.Config{
		App:   config.AppConfig{Host: "0.0.0.0", Port: 8080, AdvertisedAddress: "http://localhost:8080"},
		Cache: config.CacheConfig{Mode: config.CacheModeMem, TTL: 1 * time.Hour},
	}
	handler := NewHandler(cfg)
	handler.scanner = mock

	// Test default ANSI format (no Accept header)
	req := httptest.NewRequest("GET", "/ansi-test.com", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	contentType := w.Header().Get("Content-Type")
	if !strings.Contains(contentType, "text/plain") {
		t.Errorf("Expected text/plain content type, got %s", contentType)
	}

	body := w.Body.String()

	// Check for ANSI formatting
	if !strings.Contains(body, "nsdigup.sh") {
		t.Error("Expected nsdigup.sh header")
	}

	if !strings.Contains(body, "[ IDENTITY ]") {
		t.Error("Expected IDENTITY section")
	}

	if !strings.Contains(body, "[ CERTIFICATES ]") {
		t.Error("Expected CERTIFICATES section")
	}

	if !strings.Contains(body, "[ FINDINGS ]") {
		t.Error("Expected FINDINGS section")
	}

	// Check for content
	if !strings.Contains(body, "ansi-test.com") {
		t.Error("Expected domain name")
	}

	if !strings.Contains(body, "5.6.7.8") {
		t.Error("Expected IP address")
	}

	if !strings.Contains(body, "Test CA") {
		t.Error("Expected certificate issuer")
	}
}

func TestHandler_AcceptHeaderFormatDetection(t *testing.T) {
	mockReport := &models.Report{
		Target:   "accept-test.com",
		Identity: models.Identity{IP: "9.10.11.12"},
	}
	mock := &mockScanner{report: mockReport}

	cfg := &config.Config{
		App:   config.AppConfig{Host: "0.0.0.0", Port: 8080, AdvertisedAddress: "http://localhost:8080"},
		Cache: config.CacheConfig{Mode: config.CacheModeMem, TTL: 1 * time.Hour},
	}
	handler := NewHandler(cfg)
	handler.scanner = mock

	tests := []struct {
		name           string
		acceptHeader   string
		expectedType   string
		expectedFormat string
	}{
		{
			name:           "JSON with explicit Accept header",
			acceptHeader:   "application/json",
			expectedType:   "application/json",
			expectedFormat: "json",
		},
		{
			name:           "Text plain defaults to ANSI",
			acceptHeader:   "text/plain",
			expectedType:   "text/plain",
			expectedFormat: "ansi",
		},
		{
			name:           "Text wildcard defaults to ANSI",
			acceptHeader:   "text/*",
			expectedType:   "text/plain",
			expectedFormat: "ansi",
		},
		{
			name:           "Browser-like accept defaults to ANSI (curl-first)",
			acceptHeader:   "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			expectedType:   "text/plain",
			expectedFormat: "ansi",
		},
		{
			name:           "No Accept header defaults to ANSI",
			acceptHeader:   "",
			expectedType:   "text/plain",
			expectedFormat: "ansi",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/accept-test.com", nil)
			req.Header.Set("Accept", tt.acceptHeader)
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Expected status 200, got %d", w.Code)
			}

			contentType := w.Header().Get("Content-Type")
			if !strings.Contains(contentType, tt.expectedType) {
				t.Errorf("Expected content type %s, got %s", tt.expectedType, contentType)
			}

			body := w.Body.String()
			if tt.expectedFormat == "json" {
				if !strings.Contains(body, `"target": "accept-test.com"`) {
					t.Errorf("Expected JSON format, got: %s", body[:min(100, len(body))])
				}
			} else {
				if !strings.Contains(body, "nsdigup.sh") {
					t.Errorf("Expected ANSI format, got: %s", body[:min(100, len(body))])
				}
			}
		})
	}
}

func TestHandler_CacheWithDifferentFormats(t *testing.T) {
	mockReport := &models.Report{
		Target:   "cache-format-test.com",
		Identity: models.Identity{IP: "21.22.23.24"},
	}
	mock := &mockScanner{report: mockReport}

	cfg := &config.Config{
		App:   config.AppConfig{Host: "0.0.0.0", Port: 8080, AdvertisedAddress: "http://localhost:8080"},
		Cache: config.CacheConfig{Mode: config.CacheModeMem, TTL: 1 * time.Hour},
	}
	handler := NewHandler(cfg)
	handler.scanner = mock

	// First request as JSON
	req1 := httptest.NewRequest("GET", "/cache-format-test.com", nil)
	req1.Header.Set("Accept", "application/json")
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, req1)

	if mock.calls != 1 {
		t.Errorf("Expected 1 scanner call, got %d", mock.calls)
	}

	// Second request as ANSI - should hit cache but render differently
	req2 := httptest.NewRequest("GET", "/cache-format-test.com", nil)
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)

	// Should still be only 1 scanner call (cache hit)
	if mock.calls != 1 {
		t.Errorf("Expected still 1 scanner call (cache hit), got %d", mock.calls)
	}

	// But responses should be in different formats
	json_response := w1.Body.String()
	ansi_response := w2.Body.String()

	if strings.Contains(json_response, "nsdigup.sh") {
		t.Error("First response should be JSON, not ANSI")
	}

	if !strings.Contains(ansi_response, "nsdigup.sh") {
		t.Error("Second response should be ANSI")
	}

	// Both should contain the same data
	if !strings.Contains(json_response, "cache-format-test.com") {
		t.Error("JSON response missing domain")
	}

	if !strings.Contains(ansi_response, "cache-format-test.com") {
		t.Error("ANSI response missing domain")
	}
}
