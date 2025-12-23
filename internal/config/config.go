package config

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all application configuration
type Config struct {
	App   AppConfig   `json:"app"`
	Cache CacheConfig `json:"cache"`
}

// AppConfig holds application-level configuration
type AppConfig struct {
	Name string `json:"name"`
	Port string `json:"port"`
}

// CacheConfig holds cache-related configuration
type CacheConfig struct {
	Enabled bool          `json:"enabled"`
	TTL     time.Duration `json:"ttl"`
}

// Load loads configuration from environment variables and command line flags
// Command line flags take precedence over environment variables
func Load() (*Config, error) {
	cfg := &Config{
		App: AppConfig{
			Name: "checks.sh",
			Port: ":8080",
		},
		Cache: CacheConfig{
			Enabled: true,
			TTL:     5 * time.Minute,
		},
	}

	// Load from environment variables first
	if err := cfg.loadFromEnv(); err != nil {
		return nil, fmt.Errorf("failed to load from environment: %w", err)
	}

	// Load from command line flags (overrides env vars)
	if err := cfg.loadFromFlags(); err != nil {
		return nil, fmt.Errorf("failed to load from flags: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return cfg, nil
}

// loadFromEnv loads configuration from environment variables
func (c *Config) loadFromEnv() error {
	// App configuration
	if name := os.Getenv("CHECKS_APP_NAME"); name != "" {
		c.App.Name = name
	}

	if port := os.Getenv("CHECKS_PORT"); port != "" {
		// Ensure port starts with `:` if not provided
		if port[0] != ':' {
			port = ":" + port
		}
		c.App.Port = port
	}

	// Cache configuration
	if enabled := os.Getenv("CHECKS_CACHE_ENABLED"); enabled != "" {
		val, err := strconv.ParseBool(enabled)
		if err != nil {
			return fmt.Errorf("invalid CHECKS_CACHE_ENABLED value '%s': %w", enabled, err)
		}
		c.Cache.Enabled = val
	}

	if ttl := os.Getenv("CHECKS_CACHE_TTL"); ttl != "" {
		duration, err := time.ParseDuration(ttl)
		if err != nil {
			return fmt.Errorf("invalid CHECKS_CACHE_TTL value '%s': %w", ttl, err)
		}
		c.Cache.TTL = duration
	}

	return nil
}

// loadFromFlags loads configuration from command line flags
func (c *Config) loadFromFlags() error {
	// Only parse flags if they haven't been parsed yet and we're not in a test
	if !flag.Parsed() && !isTest() {
		var (
			appName      = flag.String("name", c.App.Name, "Application name")
			port         = flag.String("port", c.App.Port, "Server port (with or without colon prefix)")
			cacheEnabled = flag.Bool("cache", c.Cache.Enabled, "Enable caching")
			cacheTTL     = flag.Duration("cache-ttl", c.Cache.TTL, "Cache TTL duration (e.g., 5m, 1h)")
		)

		flag.Parse()

		// Apply flag values
		c.App.Name = *appName

		// Ensure port starts with `:` if not provided
		if (*port)[0] != ':' {
			c.App.Port = ":" + *port
		} else {
			c.App.Port = *port
		}

		c.Cache.Enabled = *cacheEnabled
		c.Cache.TTL = *cacheTTL
	}

	return nil
}

// isTest checks if we're running in test mode
func isTest() bool {
	for _, arg := range os.Args {
		if strings.HasPrefix(arg, "-test.") {
			return true
		}
	}
	return false
}

// validate ensures the configuration is valid
func (c *Config) validate() error {
	if c.App.Name == "" {
		return fmt.Errorf("app name cannot be empty")
	}

	if c.App.Port == "" {
		return fmt.Errorf("port cannot be empty")
	}

	if c.Cache.TTL < 0 {
		return fmt.Errorf("cache TTL cannot be negative")
	}

	// If cache is disabled, TTL doesn't matter
	if c.Cache.Enabled && c.Cache.TTL == 0 {
		return fmt.Errorf("cache TTL cannot be zero when cache is enabled")
	}

	return nil
}

// String returns a string representation of the config for debugging
func (c *Config) String() string {
	return fmt.Sprintf("Config{App: {Name: %s, Port: %s}, Cache: {Enabled: %v, TTL: %s}}",
		c.App.Name, c.App.Port, c.Cache.Enabled, c.Cache.TTL)
}
