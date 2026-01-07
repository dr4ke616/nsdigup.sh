package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"nsdigup/internal/logger"
)

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// contextKey is an unexported type to prevent collisions with context keys from other packages
type contextKey string

const loggerContextKey contextKey = "logger"

// generateRequestID creates an 8-character hexadecimal request ID using crypto/rand
func generateRequestID() (string, error) {
	b := make([]byte, 4) // 4 bytes = 8 hex characters
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// RequestIDMiddleware generates or extracts a request ID and injects a logger into the request context.
// It checks for X-Request-ID header or generates a new ID if not present.
// The request ID is always included in the X-Request-ID response header.
func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check for existing request ID from upstream
		requestID := r.Header.Get("X-Request-ID")

		// Generate new ID if not provided
		if requestID == "" {
			var err error
			requestID, err = generateRequestID()
			if err != nil {
				// Fallback to static ID on error (shouldn't happen with crypto/rand)
				requestID = "err-rand"
				logger.Get().Error("failed to generate request ID", slog.String("error", err.Error()))
			}
		}

		// Always set response header (echo back or newly generated)
		w.Header().Set("X-Request-ID", requestID)

		// Create child logger with request ID
		childLogger := logger.Get().With(slog.String("request_id", requestID))

		// Inject logger into request context
		ctx := context.WithValue(r.Context(), loggerContextKey, childLogger)

		// Continue with updated context
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetLoggerFromContext retrieves the logger from the request context.
// If no logger is found in the context, it returns the provided fallback logger.
func GetLoggerFromContext(ctx context.Context, fallback *slog.Logger) *slog.Logger {
	if logger, ok := ctx.Value(loggerContextKey).(*slog.Logger); ok {
		return logger
	}
	return fallback
}

// LoggingMiddleware logs HTTP requests with method, path, status, duration, and client details
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapped := &responseWriter{ResponseWriter: w, statusCode: 200}

		next.ServeHTTP(wrapped, r)

		duration := time.Since(start)
		domain := strings.TrimPrefix(r.URL.Path, "/")
		if domain == "" {
			domain = "home"
		}

		// Use context logger (includes request_id automatically)
		log := GetLoggerFromContext(r.Context(), logger.Get())

		log.Info("http request",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.String("domain", domain),
			slog.String("remote_addr", r.RemoteAddr),
			slog.String("user_agent", r.Header.Get("User-Agent")),
			slog.Int("status", wrapped.statusCode),
			slog.Duration("duration", duration))
	})
}
