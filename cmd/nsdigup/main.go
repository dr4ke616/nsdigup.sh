package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"nsdigup/internal/banner"
	"nsdigup/internal/config"
	"nsdigup/internal/logger"
	"nsdigup/internal/server"
)

// Version information (set via ldflags during build)
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildTime = "unknown"
)

func main() {
	// Display the banner
	banner.PrintAsciBanner()

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger
	log, err := logger.Init(cfg.Log.Level, cfg.Log.Format)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}

	serviceHandler := server.NewHandler(cfg).Router()
	wrappedHandler := server.LoggingMiddleware(serviceHandler)

	// Structured startup logs
	log.Info("application starting",
		slog.String("version", Version),
		slog.String("commit", Commit),
		slog.String("build_time", BuildTime),
		slog.String("host", cfg.App.Host),
		slog.Int("port", cfg.App.Port),
		slog.String("advertised_address", cfg.App.AdvertisedAddress),
		slog.String("cache_mode", string(cfg.Cache.Mode)),
		slog.Duration("cache_ttl", cfg.Cache.TTL),
		slog.String("log_level", cfg.Log.Level),
		slog.String("log_format", cfg.Log.Format))

	log.Info("starting http server", slog.String("address", cfg.App.Address()))

	if err := http.ListenAndServe(cfg.App.Address(), wrappedHandler); err != nil {
		log.Error("server failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
}
