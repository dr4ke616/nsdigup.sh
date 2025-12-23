package server

import (
	"net/http"
	"regexp"
	"strings"

	"checks/internal/cache"
	"checks/internal/config"
	"checks/internal/renderer"
	"checks/internal/scanner"
)

type Handler struct {
	scanner      scanner.Scanner
	cache        cache.Store
	jsonRenderer renderer.Renderer
	ansiRenderer renderer.Renderer
	config       *config.Config
}

func NewHandler(cfg *config.Config) *Handler {
	var store cache.Store

	switch cfg.Cache.Mode {
	case config.CacheModeMem:
		store = cache.NewMemoryStore(cfg.Cache.TTL)
	case config.CacheModeNone:
		store = cache.NewNoOpStore()
	default:
		// Default to no-op store for unknown cache modes
		store = cache.NewNoOpStore()
	}

	return &Handler{
		scanner:      scanner.NewOrchestrator(),
		cache:        store,
		jsonRenderer: renderer.NewJSONRenderer(),
		ansiRenderer: renderer.NewANSIRenderer(),
		config:       cfg,
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	switch {
	case isRootPath(path):
		h.ServeHome(w, r)
	case isDomainPath(path):
		h.ServeDomain(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) getOutputFormat(r *http.Request) string {
	// Check query parameter first
	if format := r.URL.Query().Get("format"); format != "" {
		return format
	}

	// Check Accept header
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") {
		return "json"
	}

	return "ansi"
}

func isDomainPath(path string) bool {
	domain := strings.TrimPrefix(path, "/")
	if domain == "" {
		return false
	}
	domainRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?(\:[0-9]+)?$`)
	return domainRegex.MatchString(domain)
}

func isRootPath(path string) bool {
	return path == "/"
}
