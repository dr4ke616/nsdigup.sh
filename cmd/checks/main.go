package main

import (
	"fmt"
	"log"
	"net/http"

	"checks/internal/config"
	"checks/internal/server"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Create handler with configuration
	handler := server.NewHandler(cfg)

	// Start server
	fmt.Printf("Starting %s on %s\n", cfg.App.Name, cfg.App.Port)
	fmt.Printf("Cache: enabled=%v, ttl=%v\n", cfg.Cache.Enabled, cfg.Cache.TTL)
	fmt.Printf("Usage: curl http://localhost%s/example.com\n", cfg.App.Port)

	if err := http.ListenAndServe(cfg.App.Port, handler); err != nil {
		log.Fatal(err)
	}
}