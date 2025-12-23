package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"checks/internal/config"
	"checks/pkg/models"
)

func TestHandler_CacheEnabled(t *testing.T) {
	mockReport := &models.Report{
		Target:   "cache-enabled-test.com",
		Identity: models.Identity{IP: "1.2.3.4"},
	}
	mock := &mockScanner{report: mockReport}

	// Create handler with cache enabled
	cfg := &config.Config{
		App: config.AppConfig{Host: "0.0.0.0", Port: ":8080"},
		Cache: config.CacheConfig{
			Enabled: true,
			TTL:     1 * time.Hour,
		},
	}
	handler := NewHandler(cfg)
	handler.scanner = mock

	// First request should hit scanner
	req1 := httptest.NewRequest("GET", "/cache-enabled-test.com", nil)
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, req1)

	if w1.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w1.Code)
	}

	if mock.calls != 1 {
		t.Errorf("Expected 1 scanner call, got %d", mock.calls)
	}

	// Second request should hit cache
	req2 := httptest.NewRequest("GET", "/cache-enabled-test.com", nil)
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w2.Code)
	}

	// Should still be only 1 scanner call (cache hit)
	if mock.calls != 1 {
		t.Errorf("Expected still 1 scanner call (cache hit), got %d", mock.calls)
	}
}

func TestHandler_CacheDisabled(t *testing.T) {
	mockReport := &models.Report{
		Target:   "cache-disabled-test.com",
		Identity: models.Identity{IP: "5.6.7.8"},
	}
	mock := &mockScanner{report: mockReport}

	// Create handler with cache disabled
	cfg := &config.Config{
		App: config.AppConfig{Host: "0.0.0.0", Port: ":8080"},
		Cache: config.CacheConfig{
			Enabled: false,
			TTL:     0, // TTL doesn't matter when disabled
		},
	}
	handler := NewHandler(cfg)
	handler.scanner = mock

	// First request should hit scanner
	req1 := httptest.NewRequest("GET", "/cache-disabled-test.com", nil)
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, req1)

	if w1.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w1.Code)
	}

	if mock.calls != 1 {
		t.Errorf("Expected 1 scanner call, got %d", mock.calls)
	}

	// Second request should also hit scanner (no caching)
	req2 := httptest.NewRequest("GET", "/cache-disabled-test.com", nil)
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w2.Code)
	}

	// Should be 2 scanner calls (no caching)
	if mock.calls != 2 {
		t.Errorf("Expected 2 scanner calls (no caching), got %d", mock.calls)
	}
}

func TestHandler_CacheVeryShortTTL(t *testing.T) {
	mockReport := &models.Report{
		Target:   "short-ttl-test.com",
		Identity: models.Identity{IP: "9.10.11.12"},
	}
	mock := &mockScanner{report: mockReport}

	// Create handler with very short TTL
	cfg := &config.Config{
		App: config.AppConfig{Host: "0.0.0.0", Port: ":8080"},
		Cache: config.CacheConfig{
			Enabled: true,
			TTL:     1 * time.Millisecond,
		},
	}
	handler := NewHandler(cfg)
	handler.scanner = mock

	// First request
	req1 := httptest.NewRequest("GET", "/short-ttl-test.com", nil)
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, req1)

	if mock.calls != 1 {
		t.Errorf("Expected 1 scanner call, got %d", mock.calls)
	}

	// Wait for cache to expire
	time.Sleep(5 * time.Millisecond)

	// Second request should miss cache and hit scanner again
	req2 := httptest.NewRequest("GET", "/short-ttl-test.com", nil)
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)

	// Should be 2 scanner calls (cache expired)
	if mock.calls != 2 {
		t.Errorf("Expected 2 scanner calls (cache expired), got %d", mock.calls)
	}
}

func TestHandler_ConfigValidation_CacheStoreType(t *testing.T) {
	tests := []struct {
		name         string
		cacheEnabled bool
		expectNoOp   bool
	}{
		{
			name:         "Cache enabled uses MemoryStore",
			cacheEnabled: true,
			expectNoOp:   false,
		},
		{
			name:         "Cache disabled uses NoOpStore",
			cacheEnabled: false,
			expectNoOp:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				App: config.AppConfig{Host: "0.0.0.0", Port: ":8080"},
				Cache: config.CacheConfig{
					Enabled: tt.cacheEnabled,
					TTL:     5 * time.Minute,
				},
			}

			handler := NewHandler(cfg)

			// Check cache size behavior to determine store type
			// NoOpStore always returns size 0, MemoryStore tracks actual size
			handler.cache.Set("test", &models.Report{Target: "test"})
			size := handler.cache.Size()

			if tt.expectNoOp && size != 0 {
				t.Error("Expected NoOpStore (size should always be 0)")
			}

			if !tt.expectNoOp && size != 1 {
				t.Error("Expected MemoryStore (size should be 1 after adding item)")
			}
		})
	}
}

func TestHandler_CacheConfigZeroTTL(t *testing.T) {
	// Cache disabled with zero TTL should work
	cfg := &config.Config{
		App: config.AppConfig{Host: "0.0.0.0", Port: ":8080"},
		Cache: config.CacheConfig{
			Enabled: false,
			TTL:     0,
		},
	}

	// Should not panic when creating handler
	handler := NewHandler(cfg)

	// Verify it uses NoOpStore
	handler.cache.Set("test", &models.Report{Target: "test"})
	if handler.cache.Size() != 0 {
		t.Error("Expected NoOpStore behavior when cache is disabled")
	}
}

func TestHandler_MultipleDomainsCacheDisabled(t *testing.T) {
	mockReport := &models.Report{
		Identity: models.Identity{IP: "13.14.15.16"},
	}
	mock := &mockScanner{report: mockReport}

	cfg := &config.Config{
		App: config.AppConfig{Host: "0.0.0.0", Port: ":8080"},
		Cache: config.CacheConfig{
			Enabled: false,
		},
	}
	handler := NewHandler(cfg)
	handler.scanner = mock

	domains := []string{"nocache1.com", "nocache2.com", "nocache3.com"}

	// Request each domain twice
	for _, domain := range domains {
		// First request
		req1 := httptest.NewRequest("GET", "/"+domain, nil)
		w1 := httptest.NewRecorder()
		handler.ServeHTTP(w1, req1)

		// Second request
		req2 := httptest.NewRequest("GET", "/"+domain, nil)
		w2 := httptest.NewRecorder()
		handler.ServeHTTP(w2, req2)

		if w1.Code != http.StatusOK || w2.Code != http.StatusOK {
			t.Errorf("Expected status 200 for domain %s", domain)
		}
	}

	// Should have 6 total calls (2 per domain, no caching)
	expectedCalls := len(domains) * 2
	if mock.calls != expectedCalls {
		t.Errorf("Expected %d scanner calls (no caching), got %d", expectedCalls, mock.calls)
	}
}
