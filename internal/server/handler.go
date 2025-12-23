package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"checks/internal/scanner"
)

type Handler struct {
	scanner scanner.Scanner
}

func NewHandler() *Handler {
	return &Handler{
		scanner: scanner.NewOrchestrator(),
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	domain := extractDomain(r.URL.Path)
	if domain == "" {
		http.Error(w, "No domain specified", http.StatusBadRequest)
		return
	}

	ctx := context.Background()
	report, err := h.scanner.Scan(ctx, domain)
	if err != nil {
		http.Error(w, "Scan failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(report); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

func extractDomain(path string) string {
	path = strings.TrimPrefix(path, "/")
	if path == "" {
		return ""
	}
	return path
}