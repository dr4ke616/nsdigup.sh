package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"checks/internal/cache"
	"checks/internal/scanner"
)

type Handler struct {
	scanner scanner.Scanner
	cache   cache.Store
}

func NewHandler(cacheTTL time.Duration) *Handler {
	return &Handler{
		scanner: scanner.NewOrchestrator(),
		cache:   cache.NewMemoryStore(cacheTTL),
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	domain := extractDomain(r.URL.Path)
	if domain == "" {
		http.Error(w, "No domain specified", http.StatusBadRequest)
		return
	}

	// Try cache first (read-through cache strategy)
	if cachedReport, found := h.cache.Get(domain); found {
		h.writeJSONResponse(w, cachedReport)
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

	h.writeJSONResponse(w, report)
}

func (h *Handler) writeJSONResponse(w http.ResponseWriter, report interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(report); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

func extractDomain(path string) string {
	path = strings.TrimPrefix(path, "/")
	if path == "" {
		return ""
	}
	return path
}