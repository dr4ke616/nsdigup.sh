package server

import (
	"context"
	"net/http"
	"strings"

	"checks/pkg/models"
)

// ServeDomain handles the "/{domain}" route for domain scanning
func (h *Handler) ServeDomain(w http.ResponseWriter, r *http.Request) {
	domain := extractDomain(r.URL.Path)
	if domain == "" {
		http.Error(w, "No domain specified", http.StatusBadRequest)
		return
	}

	// Determine output format from Accept header or query parameter
	format := h.getOutputFormat(r)

	// Try cache first (read-through cache strategy)
	if cachedReport, found := h.cache.Get(domain); found {
		h.writeResponse(w, cachedReport, format)
		return
	}

	// Cache miss - scan the domain
	ctx := context.Background()
	report, err := h.scanner.Scan(ctx, domain)
	if err != nil {
		http.Error(w, "Scan failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Store in cache for future requests
	h.cache.Set(domain, report)

	h.writeResponse(w, report, format)
}

func (h *Handler) writeResponse(w http.ResponseWriter, report interface{}, format string) {
	switch format {
	case "ansi", "text":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if err := h.ansiRenderer.Render(w, report.(*models.Report)); err != nil {
			http.Error(w, "Failed to render ANSI response: "+err.Error(), http.StatusInternalServerError)
		}
	default: // json
		w.Header().Set("Content-Type", "application/json")
		if err := h.jsonRenderer.Render(w, report.(*models.Report)); err != nil {
			http.Error(w, "Failed to render JSON response: "+err.Error(), http.StatusInternalServerError)
		}
	}
}

func extractDomain(path string) string {
	path = strings.TrimPrefix(path, "/")
	if path == "" {
		return ""
	}
	return path
}
