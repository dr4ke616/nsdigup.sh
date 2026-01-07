package server

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"nsdigup/internal/logger"
)

// TestGenerateRequestID tests the request ID generation function
func TestGenerateRequestID(t *testing.T) {
	id, err := generateRequestID()
	if err != nil {
		t.Fatalf("generateRequestID() returned error: %v", err)
	}

	// Verify length is 8 characters
	if len(id) != 8 {
		t.Errorf("Expected request ID length 8, got %d: %s", len(id), id)
	}

	// Verify hex format (lowercase a-f, 0-9)
	hexPattern := regexp.MustCompile(`^[0-9a-f]{8}$`)
	if !hexPattern.MatchString(id) {
		t.Errorf("Request ID does not match hex format: %s", id)
	}
}

// TestGenerateRequestID_Uniqueness tests that generated IDs are unique
func TestGenerateRequestID_Uniqueness(t *testing.T) {
	seen := make(map[string]bool)
	iterations := 1000

	for i := 0; i < iterations; i++ {
		id, err := generateRequestID()
		if err != nil {
			t.Fatalf("generateRequestID() returned error on iteration %d: %v", i, err)
		}

		if seen[id] {
			t.Errorf("Duplicate request ID generated: %s", id)
		}
		seen[id] = true
	}

	if len(seen) != iterations {
		t.Errorf("Expected %d unique IDs, got %d", iterations, len(seen))
	}
}

// TestRequestIDMiddleware_GeneratesID tests that middleware generates a new ID when none is provided
func TestRequestIDMiddleware_GeneratesID(t *testing.T) {
	// Initialize logger for tests
	logger.Init("info", "text")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify logger is in context
		log := GetLoggerFromContext(r.Context(), nil)
		if log == nil {
			t.Error("Expected logger in context, got nil")
		}
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	RequestIDMiddleware(handler).ServeHTTP(w, req)

	// Verify response header contains request ID
	requestID := w.Header().Get("X-Request-ID")
	if requestID == "" {
		t.Error("Expected X-Request-ID header in response, got empty")
	}

	// Verify request ID format
	if len(requestID) != 8 {
		t.Errorf("Expected request ID length 8, got %d: %s", len(requestID), requestID)
	}

	hexPattern := regexp.MustCompile(`^[0-9a-f]{8}$`)
	if !hexPattern.MatchString(requestID) {
		t.Errorf("Request ID does not match hex format: %s", requestID)
	}
}

// TestRequestIDMiddleware_WithRequestIDHeader tests that middleware uses provided X-Request-ID
func TestRequestIDMiddleware_WithRequestIDHeader(t *testing.T) {
	logger.Init("info", "text")

	expectedID := "abc12345"

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Request-ID", expectedID)
	w := httptest.NewRecorder()

	RequestIDMiddleware(handler).ServeHTTP(w, req)

	// Verify the middleware echoed back the same ID
	responseID := w.Header().Get("X-Request-ID")
	if responseID != expectedID {
		t.Errorf("Expected X-Request-ID to be %s, got %s", expectedID, responseID)
	}
}

// TestGetLoggerFromContext tests the logger extraction helper
func TestGetLoggerFromContext(t *testing.T) {
	logger.Init("info", "text")

	fallbackLogger := logger.Get()

	t.Run("Returns context logger when present", func(t *testing.T) {
		contextLogger := logger.Get().With(slog.String("test", "value"))
		ctx := context.WithValue(context.Background(), loggerContextKey, contextLogger)

		result := GetLoggerFromContext(ctx, fallbackLogger)
		if result != contextLogger {
			t.Error("Expected context logger, got different logger")
		}
	})

	t.Run("Returns fallback when context empty", func(t *testing.T) {
		ctx := context.Background()

		result := GetLoggerFromContext(ctx, fallbackLogger)
		if result != fallbackLogger {
			t.Error("Expected fallback logger when context is empty")
		}
	})

	t.Run("Returns fallback when context has wrong type", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), loggerContextKey, "not a logger")

		result := GetLoggerFromContext(ctx, fallbackLogger)
		if result != fallbackLogger {
			t.Error("Expected fallback logger when context value is wrong type")
		}
	})
}

// TestRequestIDMiddleware_Integration tests integration with LoggingMiddleware
func TestRequestIDMiddleware_Integration(t *testing.T) {
	logger.Init("info", "text")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Chain middlewares: RequestID -> Logging -> Handler
	wrappedHandler := RequestIDMiddleware(LoggingMiddleware(handler))

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(w, req)

	// Verify request ID header is present
	requestID := w.Header().Get("X-Request-ID")
	if requestID == "" {
		t.Error("Expected X-Request-ID header in response")
	}

	// Verify response
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

// TestRequestIDMiddleware_ContextPropagation tests that context is properly propagated through the chain
func TestRequestIDMiddleware_ContextPropagation(t *testing.T) {
	logger.Init("info", "text")

	var contextLogger *slog.Logger

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract logger from context
		contextLogger = GetLoggerFromContext(r.Context(), nil)
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Request-ID", "testid123")
	w := httptest.NewRecorder()

	RequestIDMiddleware(handler).ServeHTTP(w, req)

	// Verify logger was available in handler
	if contextLogger == nil {
		t.Fatal("Expected logger in context, got nil")
	}

	// The logger should be a child logger with request_id attribute
	// We can't easily verify the attribute without inspecting internal state,
	// but we can verify it's not nil and different from the global logger
	if contextLogger == logger.Get() {
		t.Error("Expected child logger, got global logger")
	}
}
