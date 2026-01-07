package server

import (
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"nsdigup/internal/cache"
	"nsdigup/internal/config"
	"nsdigup/internal/logger"
	"nsdigup/internal/renderer"
	"nsdigup/internal/scanner"
)

type Handler struct {
	scanner      scanner.Scanner
	cache        cache.Store
	jsonRenderer renderer.Renderer
	ansiRenderer renderer.Renderer
	config       *config.Config
}

func NewHandler(cfg *config.Config) *Handler {
	log := logger.Get()
	var store cache.Store

	switch cfg.Cache.Mode {
	case config.CacheModeMem:
		store = cache.NewMemoryStore(cfg.Cache.TTL)
		log.Info("cache initialized",
			slog.String("mode", "memory"),
			slog.Duration("ttl", cfg.Cache.TTL))
	case config.CacheModeNone:
		store = cache.NewNoOpStore()
		log.Info("cache initialized",
			slog.String("mode", "none"))
	default:
		store = cache.NewNoOpStore()
		log.Warn("unknown cache mode, using no-op",
			slog.String("mode", string(cfg.Cache.Mode)))
	}

	return &Handler{
		scanner:      scanner.NewScanner(),
		cache:        store,
		jsonRenderer: renderer.NewJSONRenderer(),
		ansiRenderer: renderer.NewANSIRenderer(),
		config:       cfg,
	}
}

func (h *Handler) Router() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /", h.serveRoot)
	mux.HandleFunc("GET /health", h.ServeHealth)
	mux.HandleFunc("GET /favicon.ico", h.serveMissingFavicon)

	return mux
}

func (h *Handler) serveRoot(w http.ResponseWriter, r *http.Request) {
	switch {
	case isDomainPath(r.URL.Path):
		h.ServeDomain(w, r)
	case r.URL.Path == "/":
		h.ServeHome(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) serveMissingFavicon(w http.ResponseWriter, r *http.Request) {
	http.NotFound(w, r)
}

type OutputFormat int

const (
	OutputFormatANSI OutputFormat = iota
	OutputFormatJSON
)

func (f OutputFormat) String() string {
	switch f {
	case OutputFormatANSI:
		return "ansi"
	case OutputFormatJSON:
		return "json"
	default:
		return "unknown"
	}
}

func (h *Handler) getOutputFormat(r *http.Request) OutputFormat {
	// Check Accept header
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") {
		return OutputFormatJSON
	}

	return OutputFormatANSI
}

// domainRegex validates domain names and optional ports
// Matches: example.com, sub.example.com, example.com:8080, 192.168.1.1
var domainRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?(\:[0-9]+)?$`)

func isDomainPath(path string) bool {
	domain := strings.TrimPrefix(path, "/")
	if domain == "" {
		return false
	}
	return domainRegex.MatchString(domain)
}
