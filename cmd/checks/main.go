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
	fmt.Printf("\033[1mServer:\033[0m    %s\n", cfg.App.BaseURL())
	fmt.Printf("\033[1mCache:\033[0m     mode=%s, ttl=%v\n", cfg.Cache.Mode, cfg.Cache.TTL)
	fmt.Printf("\033[1mUsage:\033[0m     curl %s/<domain>\n", cfg.App.BaseURL())
	fmt.Printf("\033[1mHome:\033[0m      curl %s/\n\n", cfg.App.BaseURL())

	if err := http.ListenAndServe(cfg.App.Address(), handler); err != nil {
		log.Fatal(err)
	}
}
