package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"checks/internal/config"
)

func TestHandler_Home_ANSI(t *testing.T) {
	cfg := &config.Config{
		App: config.AppConfig{
			Name: "Test App",
			Port: ":8080",
		},
		Cache: config.CacheConfig{
			Enabled: true,
			TTL:     5 * time.Minute,
		},
	}
	handler := NewHandler(cfg)
	
	req := httptest.NewRequest("GET", "/", nil)
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
	
	// Check for app name
	if !strings.Contains(body, "Test App") {
		t.Error("Expected app name in response")
	}
	
	// Check for usage examples
	if !strings.Contains(body, "curl http://localhost:8080/") {
		t.Error("Expected usage examples with correct port")
	}
	
	
	// Check for cache info
	if !strings.Contains(body, "5m0s TTL") {
		t.Error("Expected cache TTL information")
	}
}

func TestHandler_Home_JSON(t *testing.T) {
	cfg := &config.Config{
		App: config.AppConfig{
			Name: "JSON Test",
			Port: ":9090",
		},
		Cache: config.CacheConfig{
			Enabled: false,
			TTL:     0,
		},
	}
	handler := NewHandler(cfg)
	
	req := httptest.NewRequest("GET", "/?format=json", nil)
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
	
	// Check for JSON structure
	if !strings.Contains(body, `"name": "JSON Test"`) {
		t.Error("Expected app name in JSON")
	}
	
	// Check for usage with escaped angle brackets
	if !strings.Contains(body, `"usage": "http://localhost:9090/\u003cdomain\u003e"`) {
		t.Errorf("Expected usage with correct port in JSON, got: %s", body)
	}
	
	if !strings.Contains(body, `"enabled": false`) {
		t.Error("Expected cache disabled in JSON")
	}
	
	// Should contain examples array
	if !strings.Contains(body, `"examples"`) {
		t.Error("Expected examples in JSON response")
	}
}

func TestHandler_Home_AcceptHeader(t *testing.T) {
	cfg := &config.Config{
		App: config.AppConfig{Name: "Accept Test", Port: ":8080"},
		Cache: config.CacheConfig{Enabled: true, TTL: 5 * time.Minute},
	}
	handler := NewHandler(cfg)
	
	tests := []struct {
		name        string
		acceptHeader string
		expectedType string
		expectedFormat string
	}{
		{
			name:          "JSON Accept header",
			acceptHeader:  "application/json",
			expectedType:  "application/json",
			expectedFormat: "json",
		},
		{
			name:          "Text Accept header",
			acceptHeader:  "text/plain",
			expectedType:  "text/plain",
			expectedFormat: "ansi",
		},
		{
			name:          "Default (no Accept)",
			acceptHeader:  "",
			expectedType:  "text/plain",
			expectedFormat: "ansi",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			if tt.acceptHeader != "" {
				req.Header.Set("Accept", tt.acceptHeader)
			}
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
				if !strings.Contains(body, `"name": "Accept Test"`) {
					t.Error("Expected JSON format")
				}
			} else {
				if !strings.Contains(body, "Accept Test") {
					t.Error("Expected ANSI format")
				}
			}
		})
	}
}

func TestHandler_Home_CacheDisabled(t *testing.T) {
	cfg := &config.Config{
		App: config.AppConfig{
			Name: "No Cache Test",
			Port: ":8080",
		},
		Cache: config.CacheConfig{
			Enabled: false,
			TTL:     0,
		},
	}
	handler := NewHandler(cfg)
	
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	
	body := w.Body.String()
	
	// Should indicate real-time scanning when cache is disabled
	if !strings.Contains(body, "Real-time Scanning") {
		t.Error("Expected real-time scanning message when cache disabled")
	}
}

func TestHandler_Home_CacheEnabled(t *testing.T) {
	cfg := &config.Config{
		App: config.AppConfig{
			Name: "Cache Test",
			Port: ":8080",
		},
		Cache: config.CacheConfig{
			Enabled: true,
			TTL:     10 * time.Minute,
		},
	}
	handler := NewHandler(cfg)
	
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	
	body := w.Body.String()
	
	// Should show cache TTL when cache is enabled
	if !strings.Contains(body, "10m0s TTL") {
		t.Error("Expected cache TTL message when cache enabled")
	}
}

func TestHandler_Home_CustomPort(t *testing.T) {
	cfg := &config.Config{
		App: config.AppConfig{
			Name: "Custom Port",
			Port: ":9999",
		},
		Cache: config.CacheConfig{Enabled: true, TTL: 5 * time.Minute},
	}
	handler := NewHandler(cfg)
	
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	
	body := w.Body.String()
	
	// Should use the configured port in examples
	if !strings.Contains(body, "http://localhost:9999/") {
		t.Error("Expected custom port in examples")
	}
}