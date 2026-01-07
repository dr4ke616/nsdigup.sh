package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"nsdigup/internal/logger"
	"nsdigup/pkg/models"
)

// ServeDomain handles the "/{domain}" route for domain scanning
func (h *Handler) ServeDomain(w http.ResponseWriter, r *http.Request) {
	log := GetLoggerFromContext(r.Context(), logger.Get())

	domain := extractDomain(r.URL.Path)
	if domain == "" {
		log.Warn("invalid request: no domain specified",
			slog.String("path", r.URL.Path),
			slog.String("remote_addr", r.RemoteAddr))
		http.Error(w, "No domain specified", http.StatusBadRequest)
		return
	}

	// Determine output format from Accept header
	format := h.getOutputFormat(r)
	log.Debug("processing domain check",
		slog.String("domain", domain),
		slog.String("format", format.String()))

	// Try cache first (read-through cache strategy)
	if cachedReport, found := h.cache.Get(domain); found {
		log.Info("cache hit", slog.String("domain", domain))
		h.writeResponse(w, r, cachedReport, format)
		return
	}

	// Cache miss - scan the domain
	log.Info("cache miss, initiating scan", slog.String("domain", domain))

	start := time.Now()
	ctx := context.Background()
	report, err := h.scanner.Scan(ctx, domain)
	scanDuration := time.Since(start)

	if err != nil {
		log.Error("domain scan failed",
			slog.String("domain", domain),
			slog.String("error", err.Error()),
			slog.Duration("duration", scanDuration))
		http.Error(w, "Scan failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	log.Info("scan completed",
		slog.String("domain", domain),
		slog.Duration("duration", scanDuration))

	// Store in cache for future requests
	h.cache.Set(domain, report)

	h.writeResponse(w, r, report, format)
}

func (h *Handler) writeResponse(w http.ResponseWriter, r *http.Request, report *models.Report, format OutputFormat) {
	log := GetLoggerFromContext(r.Context(), logger.Get())

	switch format {
	case OutputFormatANSI:
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(200)
		if err := h.ansiRenderer.Render(w, report); err != nil {
			log.Error("failed to render ANSI response",
				slog.String("error", err.Error()))
			http.Error(w, "Failed to render ANSI response: "+err.Error(), http.StatusInternalServerError)
		}
	case OutputFormatJSON:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		if err := h.jsonRenderer.Render(w, report); err != nil {
			log.Error("failed to render JSON response",
				slog.String("error", err.Error()))
			http.Error(w, "Failed to render JSON response: "+err.Error(), http.StatusInternalServerError)
		}
	default:
		// This should never happen if OutputFormat enum is properly maintained
		panic(fmt.Sprintf("unsupported output format: %v", format))
	}
}

func extractDomain(path string) string {
	path = strings.TrimPrefix(path, "/")
	if path == "" {
		return ""
	}
	return path
}
