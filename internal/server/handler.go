package server

import (
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"checks/internal/cache"
	"checks/internal/config"
	"checks/internal/logger"
	"checks/internal/renderer"
	"checks/internal/scanner"
)

type Handler struct {
	scanner      scanner.Scanner
	cache        cache.Store
	jsonRenderer renderer.Renderer
	ansiRenderer renderer.Renderer
	config       *config.Config
	logger       *slog.Logger
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
		scanner:      scanner.NewOrchestrator(),
		cache:        store,
		jsonRenderer: renderer.NewJSONRenderer(),
		ansiRenderer: renderer.NewANSIRenderer(),
		config:       cfg,
		logger:       log,
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	switch {
	case isRootPath(path):
		h.ServeHome(w, r)
	case isHealthPath(path):
		h.ServeHealth(w, r)
	case isDomainPath(path):
		h.ServeDomain(w, r)
	default:
		http.NotFound(w, r)
	}
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

func isHealthPath(path string) bool {
	return path == "/health"
}
