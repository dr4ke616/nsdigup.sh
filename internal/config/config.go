package config

import (
	"flag"
	"fmt"
	"os"
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
	Host string `json:"host"`
	Port string `json:"port"`
}

// Address returns the full host:port address for the server
func (a *AppConfig) Address() string {
	return a.Host + a.Port
}

// BaseURL returns the base URL for the server
func (a *AppConfig) BaseURL() string {
	return "http://" + a.Host + a.Port
}

// CacheMode represents the cache implementation mode
type CacheMode string

const (
	CacheModeNone CacheMode = "none"
	CacheModeMem  CacheMode = "mem"
)

// CacheConfig holds cache-related configuration
type CacheConfig struct {
	Mode CacheMode     `json:"mode"`
	TTL  time.Duration `json:"ttl"`
}

// Load loads configuration from environment variables and command line flags
// Command line flags take precedence over environment variables
func Load() (*Config, error) {
	cfg := &Config{
		App: AppConfig{
			Name: "checks.sh",
			Host: "0.0.0.0",
			Port: ":8080",
		},
		Cache: CacheConfig{
			Mode: CacheModeMem,
			TTL:  5 * time.Minute,
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

	if host := os.Getenv("CHECKS_HOST"); host != "" {
		c.App.Host = host
	}

	if port := os.Getenv("CHECKS_PORT"); port != "" {
		// Ensure port starts with `:` if not provided
		if port[0] != ':' {
			port = ":" + port
		}
		c.App.Port = port
	}

	// Cache configuration
	if mode := os.Getenv("CHECKS_CACHE_MODE"); mode != "" {
		switch CacheMode(mode) {
		case CacheModeNone, CacheModeMem:
			c.Cache.Mode = CacheMode(mode)
		default:
			return fmt.Errorf("invalid CHECKS_CACHE_MODE value '%s': must be 'none' or 'mem'", mode)
		}
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
			appName   = flag.String("name", c.App.Name, "Application name")
			host      = flag.String("host", c.App.Host, "Server host address")
			port      = flag.String("port", c.App.Port, "Server port (with or without colon prefix)")
			cacheMode = flag.String("cache-mode", string(c.Cache.Mode), "Cache mode: 'none' or 'mem'")
			cacheTTL  = flag.Duration("cache-ttl", c.Cache.TTL, "Cache TTL duration (e.g., 5m, 1h)")
		)

		flag.Parse()

		// Apply flag values
		c.App.Name = *appName
		c.App.Host = *host

		// Ensure port starts with `:` if not provided
		if (*port)[0] != ':' {
			c.App.Port = ":" + *port
		} else {
			c.App.Port = *port
		}

		// Validate and set cache mode
		switch CacheMode(*cacheMode) {
		case CacheModeNone, CacheModeMem:
			c.Cache.Mode = CacheMode(*cacheMode)
		default:
			return fmt.Errorf("invalid cache-mode value '%s': must be 'none' or 'mem'", *cacheMode)
		}

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
	if c.Cache.Mode == CacheModeMem && c.Cache.TTL == 0 {
		return fmt.Errorf("cache TTL cannot be zero when cache is enabled")
	}

	return nil
}

// String returns a string representation of the config for debugging
func (c *Config) String() string {
	return fmt.Sprintf("Config{App: {Name: %s, Port: %s}, Cache: {Mode: %v, TTL: %s}}",
		c.App.Name, c.App.Port, c.Cache.Mode, c.Cache.TTL)
}
