package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"nsdigup/internal/config"
)

func TestHandler_Home_ANSI(t *testing.T) {
	cfg := &config.Config{
		App: config.AppConfig{
			AdvertisedAddress: "http://foo",
			Host:              "0.0.0.0",
			Port:              8080,
		},
		Cache: config.CacheConfig{
			Mode: config.CacheModeMem,
			TTL:  5 * time.Minute,
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

	// Check for usage examples with advertised address
	if !strings.Contains(body, "curl http://foo/") {
		t.Error("Expected usage examples with advertised address")
	}

	// Check for features
	if !strings.Contains(body, "DNS Resolution") {
		t.Error("Expected feature description")
	}
}

func TestHandler_Home_JSON(t *testing.T) {
	cfg := &config.Config{
		App: config.AppConfig{
			AdvertisedAddress: "http://foo",
			Host:              "127.0.0.1",
			Port:              9090,
		},
		Cache: config.CacheConfig{
			Mode: config.CacheModeNone,
			TTL:  0,
		},
	}
	handler := NewHandler(cfg)

	req := httptest.NewRequest("GET", "/", nil)
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

	// Check for JSON structure
	if !strings.Contains(body, `"name": "nsdigup.sh"`) {
		t.Errorf("Expected name in JSON, got: %s", body)
	}
}

func TestHandler_Home_AcceptHeader(t *testing.T) {
	cfg := &config.Config{
		App:   config.AppConfig{AdvertisedAddress: "http://foo", Host: "0.0.0.0", Port: 8080},
		Cache: config.CacheConfig{Mode: config.CacheModeMem, TTL: 5 * time.Minute},
	}
	handler := NewHandler(cfg)

	tests := []struct {
		name           string
		acceptHeader   string
		expectedType   string
		expectedFormat string
	}{
		{
			name:           "JSON Accept header",
			acceptHeader:   "application/json",
			expectedType:   "application/json",
			expectedFormat: "json",
		},
		{
			name:           "Text Accept header",
			acceptHeader:   "text/plain",
			expectedType:   "text/plain",
			expectedFormat: "ansi",
		},
		{
			name:           "Default (no Accept)",
			acceptHeader:   "",
			expectedType:   "text/plain",
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
				if !strings.Contains(body, `"name": "nsdigup.sh"`) {
					t.Error("Expected JSON format")
				}
			} else {
				if !strings.Contains(body, "Features:") {
					t.Error("Expected ANSI format")
				}
			}
		})
	}
}

func TestHandler_Home_CacheDisabled(t *testing.T) {
	cfg := &config.Config{
		App: config.AppConfig{
			AdvertisedAddress: "http://foo",
			Host:              "0.0.0.0",
			Port:              8080,
		},
		Cache: config.CacheConfig{
			Mode: config.CacheModeNone,
			TTL:  0,
		},
	}
	handler := NewHandler(cfg)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestHandler_Home_CacheEnabled(t *testing.T) {
	cfg := &config.Config{
		App: config.AppConfig{
			AdvertisedAddress: "http://foo",
			Host:              "0.0.0.0",
			Port:              8080,
		},
		Cache: config.CacheConfig{
			Mode: config.CacheModeMem,
			TTL:  10 * time.Minute,
		},
	}
	handler := NewHandler(cfg)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestHandler_Home_CustomPort(t *testing.T) {
	cfg := &config.Config{
		App: config.AppConfig{
			AdvertisedAddress: "http://custom.example.com",
			Host:              "192.168.1.100",
			Port:              9999,
		},
		Cache: config.CacheConfig{Mode: config.CacheModeMem, TTL: 5 * time.Minute},
	}
	handler := NewHandler(cfg)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	body := w.Body.String()

	// Should use the advertised address in examples
	if !strings.Contains(body, "http://custom.example.com/") {
		t.Error("Expected advertised address in examples")
	}
}
