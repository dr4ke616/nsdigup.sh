package main

import (
	"fmt"
	"log"
	"net/http"

	"checks/internal/banner"
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

	// Display startup banner
	fmt.Print(banner.Generate(cfg.App.Name))
	fmt.Printf("\n\n\033[1m\033[32m%s\033[0m - Domain Health Checker\n\n", cfg.App.Name)
	fmt.Printf("\033[1mServer:\033[0m    http://localhost%s\n", cfg.App.Port)
	fmt.Printf("\033[1mCache:\033[0m     enabled=%v, ttl=%v\n", cfg.Cache.Enabled, cfg.Cache.TTL)
	fmt.Printf("\033[1mUsage:\033[0m     curl http://localhost%s/<domain>\n", cfg.App.Port)
	fmt.Printf("\033[1mHome:\033[0m      curl http://localhost%s/\n\n", cfg.App.Port)

	if err := http.ListenAndServe(cfg.App.Port, handler); err != nil {
		log.Fatal(err)
	}
}
