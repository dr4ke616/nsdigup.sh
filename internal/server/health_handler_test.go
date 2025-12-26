package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"nsdigup/internal/config"
)

func TestHandler_ServeHealth(t *testing.T) {
	cfg := &config.Config{
		App:   config.AppConfig{Host: "0.0.0.0", Port: 8080, AdvertisedAddress: "http://localhost:8080"},
		Cache: config.CacheConfig{Mode: config.CacheModeMem, TTL: 1 * time.Hour},
	}
	handler := NewHandler(cfg)

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type application/json, got %s", contentType)
	}

	var response map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Errorf("Failed to parse JSON response: %v", err)
	}

	if response["status"] != "ok" {
		t.Errorf("Expected status 'ok', got '%s'", response["status"])
	}
}
