package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"nsdigup/pkg/models"
)

// ServeDomain handles the "/{domain}" route for domain scanning
func (h *Handler) ServeDomain(w http.ResponseWriter, r *http.Request) {
	domain := extractDomain(r.URL.Path)
	if domain == "" {
		h.logger.Warn("invalid request: no domain specified",
			slog.String("path", r.URL.Path),
			slog.String("remote_addr", r.RemoteAddr))
		http.Error(w, "No domain specified", http.StatusBadRequest)
		return
	}

	// Determine output format from Accept header
	format := h.getOutputFormat(r)
	h.logger.Debug("processing domain check",
		slog.String("domain", domain),
		slog.String("format", format.String()))

	cacheStore := h.getCache()
	scanner := h.getScanner()

	// Try cache first (read-through cache strategy)
	if cacheStore != nil {
		if cachedReport, found := cacheStore.Get(domain); found {
			h.logger.Info("cache hit", slog.String("domain", domain))
			h.writeResponse(w, cachedReport, format)
			return
		}
	}

	if scanner == nil {
		h.logger.Error("scanner not configured",
			slog.String("domain", domain))
		http.Error(w, "Scanner not available", http.StatusInternalServerError)
		return
	}

	// Cache miss - scan the domain
	h.logger.Info("cache miss, initiating scan", slog.String("domain", domain))

	start := time.Now()
	ctx := context.Background()
	report, err := scanner.Scan(ctx, domain)
	scanDuration := time.Since(start)

	if err != nil {
		h.logger.Error("domain scan failed",
			slog.String("domain", domain),
			slog.String("error", err.Error()),
			slog.Duration("duration", scanDuration))
		http.Error(w, "Scan failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	h.logger.Info("scan completed",
		slog.String("domain", domain),
		slog.Duration("duration", scanDuration))

	// Store in cache for future requests
	if cacheStore != nil {
		cacheStore.Set(domain, report)
	}

	h.writeResponse(w, report, format)
}

func (h *Handler) writeResponse(w http.ResponseWriter, report *models.Report, format OutputFormat) {
	ansiRenderer := h.getANSIRenderer()
	jsonRenderer := h.getJSONRenderer()

	switch format {
	case OutputFormatANSI:
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(200)
		if ansiRenderer == nil {
			h.logger.Error("failed to render ANSI response", slog.String("error", "renderer not configured"))
			http.Error(w, "Failed to render ANSI response: renderer not available", http.StatusInternalServerError)
			return
		}
		if err := ansiRenderer.Render(w, report); err != nil {
			h.logger.Error("failed to render ANSI response",
				slog.String("error", err.Error()))
			http.Error(w, "Failed to render ANSI response: "+err.Error(), http.StatusInternalServerError)
		}
	case OutputFormatJSON:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		if jsonRenderer == nil {
			h.logger.Error("failed to render JSON response", slog.String("error", "renderer not configured"))
			http.Error(w, "Failed to render JSON response: renderer not available", http.StatusInternalServerError)
			return
		}
		if err := jsonRenderer.Render(w, report); err != nil {
			h.logger.Error("failed to render JSON response",
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
