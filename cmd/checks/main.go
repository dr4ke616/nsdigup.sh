package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"checks/internal/banner"
	"checks/internal/config"
	"checks/internal/logger"
	"checks/internal/server"
)

// Version information (set via ldflags during build)
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildTime = "unknown"
)

func main() {
	// Parse command-line flags
	versionFlag := flag.Bool("version", false, "Print version information and exit")
	flag.Parse()

	// Handle version flag
	if *versionFlag {
		fmt.Printf("checks version %s\n", Version)
		fmt.Printf("  commit: %s\n", Commit)
		fmt.Printf("  built: %s\n", BuildTime)
		os.Exit(0)
	}

	// display the banner
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

	// Create handler with configuration and wrap it using a logging middleware
	handler := server.LoggingMiddleware(server.NewHandler(cfg))

	// Structured startup logs
	log.Info("application starting",
		slog.String("host", cfg.App.Host),
		slog.Int("port", cfg.App.Port),
		slog.String("advertised_address", cfg.App.AdvertisedAddress),
		slog.String("cache_mode", string(cfg.Cache.Mode)),
		slog.Duration("cache_ttl", cfg.Cache.TTL),
		slog.String("log_level", cfg.Log.Level),
		slog.String("log_format", cfg.Log.Format))

	log.Info("starting http server", slog.String("address", cfg.App.Address()))

	if err := http.ListenAndServe(cfg.App.Address(), handler); err != nil {
		log.Error("server failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
}
