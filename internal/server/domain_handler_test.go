package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"checks/internal/config"
	"checks/pkg/models"
)

// Mock scanner for testing
type mockScanner struct {
	report *models.Report
	err    error
	calls  int
}

func (m *mockScanner) Scan(ctx context.Context, domain string) (*models.Report, error) {
	m.calls++
	if m.err != nil {
		return nil, m.err
	}

	// Return a copy to avoid race conditions
	report := *m.report
	report.Target = domain
	report.Timestamp = time.Now()
	return &report, nil
}

func TestHandler_CacheHit(t *testing.T) {
	// Create mock scanner
	mockReport := &models.Report{
		Target:   "example.com",
		Identity: models.Identity{IP: "192.168.1.1"},
	}
	mock := &mockScanner{report: mockReport}

	// Create handler with cache enabled
	cfg := &config.Config{
		App: config.AppConfig{Host: "0.0.0.0", Port: 8080, AdvertisedAddress: "http://localhost:8080"},
		Cache: config.CacheConfig{
			Mode: config.CacheModeMem,
			TTL:  1 * time.Hour,
		},
	}
	handler := NewHandler(cfg)
	handler.scanner = mock

	// First request - should hit scanner
	req1 := httptest.NewRequest("GET", "/example.com", nil)
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, req1)

	if w1.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w1.Code)
	}

	if mock.calls != 1 {
		t.Errorf("Expected 1 scanner call, got %d", mock.calls)
	}

	// Second request - should hit cache
	req2 := httptest.NewRequest("GET", "/example.com", nil)
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w2.Code)
	}

	if mock.calls != 1 {
		t.Errorf("Expected still 1 scanner call (cache hit), got %d", mock.calls)
	}

	// Verify both responses are the same
	var resp1, resp2 models.Report
	json.Unmarshal(w1.Body.Bytes(), &resp1)
	json.Unmarshal(w2.Body.Bytes(), &resp2)

	if resp1.Identity.IP != resp2.Identity.IP {
		t.Error("Cache hit should return same data")
	}
}

func TestHandler_CacheMiss(t *testing.T) {
	mockReport := &models.Report{
		Target:   "example.com",
		Identity: models.Identity{IP: "192.168.1.1"},
	}
	mock := &mockScanner{report: mockReport}

	// Create handler with very short TTL
	cfg := &config.Config{
		App:   config.AppConfig{Host: "0.0.0.0", Port: 8080, AdvertisedAddress: "http://localhost:8080"},
		Cache: config.CacheConfig{Mode: config.CacheModeMem, TTL: 1 * time.Millisecond},
	}
	handler := NewHandler(cfg)
	handler.scanner = mock

	// First request
	req1 := httptest.NewRequest("GET", "/example.com", nil)
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, req1)

	if mock.calls != 1 {
		t.Errorf("Expected 1 scanner call, got %d", mock.calls)
	}

	// Wait for cache to expire
	time.Sleep(5 * time.Millisecond)

	// Second request - should miss cache and hit scanner again
	req2 := httptest.NewRequest("GET", "/example.com", nil)
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)

	if mock.calls != 2 {
		t.Errorf("Expected 2 scanner calls (cache miss), got %d", mock.calls)
	}
}

func TestHandler_MultipleDomains(t *testing.T) {
	mockReport := &models.Report{
		Identity: models.Identity{IP: "192.168.1.1"},
	}
	mock := &mockScanner{report: mockReport}

	cfg := &config.Config{
		App:   config.AppConfig{Host: "0.0.0.0", Port: 8080, AdvertisedAddress: "http://localhost:8080"},
		Cache: config.CacheConfig{Mode: config.CacheModeMem, TTL: 1 * time.Hour},
	}
	handler := NewHandler(cfg)
	handler.scanner = mock

	domains := []string{"google.com", "github.com", "example.com"}

	// Request each domain once
	for _, domain := range domains {
		req := httptest.NewRequest("GET", "/"+domain, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200 for %s, got %d", domain, w.Code)
		}
	}

	// Should have 3 scanner calls (one per domain)
	if mock.calls != len(domains) {
		t.Errorf("Expected %d scanner calls, got %d", len(domains), mock.calls)
	}

	// Request each domain again - should all be cache hits
	for _, domain := range domains {
		req := httptest.NewRequest("GET", "/"+domain, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200 for %s, got %d", domain, w.Code)
		}
	}

	// Should still have only 3 scanner calls
	if mock.calls != len(domains) {
		t.Errorf("Expected still %d scanner calls (cache hits), got %d", len(domains), mock.calls)
	}
}

func TestHandler_ScannerError(t *testing.T) {
	mock := &mockScanner{
		err: context.DeadlineExceeded,
	}

	cfg := &config.Config{
		App:   config.AppConfig{Host: "0.0.0.0", Port: 8080, AdvertisedAddress: "http://localhost:8080"},
		Cache: config.CacheConfig{Mode: config.CacheModeMem, TTL: 1 * time.Hour},
	}
	handler := NewHandler(cfg)
	handler.scanner = mock

	req := httptest.NewRequest("GET", "/example.com", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500 on scanner error, got %d", w.Code)
	}

	// Error should not be cached - try again
	req2 := httptest.NewRequest("GET", "/example.com", nil)
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)

	if mock.calls != 2 {
		t.Errorf("Expected 2 scanner calls (error not cached), got %d", mock.calls)
	}
}

func TestHandler_EmptyDomain(t *testing.T) {
	cfg := &config.Config{
		App:   config.AppConfig{Host: "0.0.0.0", Port: 8080, AdvertisedAddress: "http://localhost:8080"},
		Cache: config.CacheConfig{Mode: config.CacheModeMem, TTL: 1 * time.Hour},
	}
	handler := NewHandler(cfg)

	// "/" is now the home route, should return 200
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200 for home route /, got %d", w.Code)
	}

	// "http://localhost/" is also treated as home route
	req2 := httptest.NewRequest("GET", "http://localhost/", nil)
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("Expected status 200 for home route http://localhost/, got %d", w2.Code)
	}
}

func TestHandler_JSONResponse(t *testing.T) {
	mockReport := &models.Report{
		Target: "example.com",
		Identity: models.Identity{
			IP:          "192.168.1.1",
			Nameservers: []string{"ns1.example.com", "ns2.example.com"},
		},
		Certificates: models.Certificates{
			Current: models.CertDetails{
				Issuer:     "Test CA",
				CommonName: "example.com",
				Status:     "Active",
				IsWildcard: false,
			},
		},
	}
	mock := &mockScanner{report: mockReport}

	cfg := &config.Config{
		App:   config.AppConfig{Host: "0.0.0.0", Port: 8080, AdvertisedAddress: "http://localhost:8080"},
		Cache: config.CacheConfig{Mode: config.CacheModeMem, TTL: 1 * time.Hour},
	}
	handler := NewHandler(cfg)
	handler.scanner = mock

	req := httptest.NewRequest("GET", "/example.com", nil)
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	contentType := w.Header().Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		t.Errorf("Expected Content-Type application/json, got %s", contentType)
	}

	var response models.Report
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Errorf("Failed to unmarshal JSON response: %v", err)
	}

	if response.Target != "example.com" {
		t.Errorf("Expected target example.com, got %s", response.Target)
	}

	if response.Identity.IP != "192.168.1.1" {
		t.Errorf("Expected IP 192.168.1.1, got %s", response.Identity.IP)
	}

	if len(response.Identity.Nameservers) != 2 {
		t.Errorf("Expected 2 nameservers, got %d", len(response.Identity.Nameservers))
	}
}
