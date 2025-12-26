package server

import (
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

		logger.Get().Info("http request",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.String("domain", domain),
			slog.String("remote_addr", r.RemoteAddr),
			slog.String("user_agent", r.Header.Get("User-Agent")),
			slog.Int("status", wrapped.statusCode),
			slog.Duration("duration", duration))
	})
}
