package config

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	// Application server configuration
	App AppConfig `json:"app"`
	// Caching configuration
	Cache CacheConfig `json:"cache"`
}

type AppConfig struct {
	// The hostname for which the application runs
	Host string `json:"host"`
	// The port for which the application runs
	Port int `json:"port"`
	// The address in which is exposed publically as the application entry point
	AdvertisedAddress string `json:"advertised_address"`
}

func (a *AppConfig) Address() string {
	return fmt.Sprintf("%s:%d", a.Host, a.Port)
}

func (a *AppConfig) BaseURL() string {
	return fmt.Sprintf("http://%s:%d", a.Host, a.Port)
}

type CacheMode string

const (
	CacheModeNone CacheMode = "none"
	CacheModeMem  CacheMode = "mem"
)

type CacheConfig struct {
	// Caching mode to run, either "mem" for in memory store or "none" for a no-op store.
	Mode CacheMode `json:"mode"`
	// For how long each cached record is to sit in store
	TTL time.Duration `json:"ttl"`
}

// Load loads configuration from environment variables and command line flags
// Command line flags take precedence over environment variables
func Load() (*Config, error) {
	cfg := &Config{
		App: AppConfig{
			AdvertisedAddress: "http://checks.sh",
			Host:              "0.0.0.0",
			Port:              8080,
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
	if addr := os.Getenv("CHECKS_ADVERTISED_ADDRESS"); addr != "" {
		c.App.AdvertisedAddress = addr
	}

	if host := os.Getenv("CHECKS_HOST"); host != "" {
		c.App.Host = host
	}

	if port := os.Getenv("CHECKS_PORT"); port != "" {
		p, err := strconv.Atoi(port)
		if err != nil {
			return fmt.Errorf("invalid CHECKS_PORT value '%s': %w", port, err)
		}
		c.App.Port = p
	}

	if ttl := os.Getenv("CHECKS_CACHE_TTL"); ttl != "" {
		duration, err := time.ParseDuration(ttl)
		if err != nil {
			return fmt.Errorf("invalid CHECKS_CACHE_TTL value '%s': %w", ttl, err)
		}
		c.Cache.TTL = duration
	}

	if mode := os.Getenv("CHECKS_CACHE_MODE"); mode != "" {
		switch CacheMode(mode) {
		case CacheModeNone:
			c.Cache.Mode = CacheModeNone
		case CacheModeMem:
			c.Cache.Mode = CacheModeMem
		default:
			return fmt.Errorf("invalid CHECKS_CACHE_MODE value '%s': must be 'none' or 'mem'", mode)
		}
	}

	return nil
}

func (c *Config) loadFromFlags() error {
	if !flag.Parsed() && !isTest() {
		var (
			host              = flag.String("host", c.App.Host, "Server host address")
			port              = flag.Int("port", c.App.Port, "Server port to bind to")
			advertisedAddress = flag.String("name", c.App.AdvertisedAddress, "The address in which is exposed publically as the application entry point")
			cacheMode         = flag.String("cache-mode", string(c.Cache.Mode), "Cache mode: 'none' or 'mem'")
			cacheTTL          = flag.Duration("cache-ttl", c.Cache.TTL, "Cache TTL duration (e.g., 5m, 1h)")
		)

		flag.Parse()

		c.App.AdvertisedAddress = *advertisedAddress
		c.App.Host = *host
		c.App.Port = *port
		c.Cache.TTL = *cacheTTL

		switch CacheMode(*cacheMode) {
		case CacheModeNone:
			c.Cache.Mode = CacheModeNone
		case CacheModeMem:
			c.Cache.Mode = CacheModeMem
		default:
			return fmt.Errorf("invalid cache-mode value '%s': must be 'none' or 'mem'", *cacheMode)
		}
	}

	return nil
}

// isTest checks if we're running in test mode - just to avoid issues when parsing flags
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
	if c.App.Port < 0 || c.App.Port > 65_535 {
		return fmt.Errorf("port must be in range 0-65535")
	}

	if c.Cache.TTL < 0 {
		return fmt.Errorf("cache TTL cannot be negative")
	}

	if c.App.AdvertisedAddress == "" {
		return fmt.Errorf("advertised address cannot be empty")
	}

	// If cache is disabled, TTL doesn't matter
	if c.Cache.Mode == CacheModeMem && c.Cache.TTL == 0 {
		return fmt.Errorf("cache TTL cannot be zero when cache is enabled")
	}

	return nil
}

// String returns a string representation of the config for debugging
func (c *Config) String() string {
	return fmt.Sprintf("Config{App: {Host: %s, Port: %d, AdvertisedAddress: %s}, Cache: {Mode: %v, TTL: %s}}",
		c.App.Host, c.App.Port, c.App.AdvertisedAddress, c.Cache.Mode, c.Cache.TTL)
}
