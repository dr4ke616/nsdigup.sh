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
	scanner      *scanner.Scanner
	cache        *cache.Store
	jsonRenderer *renderer.Renderer
	ansiRenderer *renderer.Renderer
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

	scannerImpl := scanner.Scanner(scanner.NewScanner())
	jsonRenderer := renderer.Renderer(renderer.NewJSONRenderer())
	ansiRenderer := renderer.Renderer(renderer.NewANSIRenderer())

	return &Handler{
		scanner:      &scannerImpl,
		cache:        &store,
		jsonRenderer: &jsonRenderer,
		ansiRenderer: &ansiRenderer,
		config:       cfg,
		logger:       log,
	}
}

func (h *Handler) SetScanner(sc scanner.Scanner) {
	h.scanner = &sc
}

func (h *Handler) getScanner() scanner.Scanner {
	if h.scanner == nil {
		return nil
	}
	return *h.scanner
}

func (h *Handler) getCache() cache.Store {
	if h.cache == nil {
		return nil
	}
	return *h.cache
}

func (h *Handler) getJSONRenderer() renderer.Renderer {
	if h.jsonRenderer == nil {
		return nil
	}
	return *h.jsonRenderer
}

func (h *Handler) getANSIRenderer() renderer.Renderer {
	if h.ansiRenderer == nil {
		return nil
	}
	return *h.ansiRenderer
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	switch {
	case isRootPath(path):
		h.ServeHome(w, r)
	case isHealthPath(path):
		h.ServeHealth(w, r)
	case isFaviconPath(path):
		http.NotFound(w, r)
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

func isFaviconPath(path string) bool {
	return path == "/favicon.ico"
}
