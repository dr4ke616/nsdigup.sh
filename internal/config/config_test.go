package config

import (
	"flag"
	"os"
	"testing"
	"time"
)

func TestConfig_Load_Defaults(t *testing.T) {
	// Clear environment variables
	clearEnv()

	// Reset flag parsing for test
	resetFlags()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Check default values
	if cfg.App.AdvertisedAddress != "http://checks.sh" {
		t.Errorf("Expected advertised address 'http://checks.sh', got '%s'", cfg.App.AdvertisedAddress)
	}

	if cfg.App.Port != 8080 {
		t.Errorf("Expected port 8080, got %d", cfg.App.Port)
	}

	if cfg.Cache.Mode != CacheModeMem {
		t.Error("Expected cache mem mode by default")
	}

	if cfg.Cache.TTL != 5*time.Minute {
		t.Errorf("Expected cache TTL '5m', got '%v'", cfg.Cache.TTL)
	}
}

func TestConfig_LoadFromEnv(t *testing.T) {
	// Clear environment
	clearEnv()
	resetFlags()

	// Set environment variables
	os.Setenv("CHECKS_ADVERTISED_ADDRESS", "http://test-app.com")
	os.Setenv("CHECKS_PORT", "9090")
	os.Setenv("CHECKS_CACHE_MODE", "none")
	os.Setenv("CHECKS_CACHE_TTL", "10m")
	defer clearEnv()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if cfg.App.AdvertisedAddress != "http://test-app.com" {
		t.Errorf("Expected advertised address 'http://test-app.com', got '%s'", cfg.App.AdvertisedAddress)
	}

	if cfg.App.Port != 9090 {
		t.Errorf("Expected port 9090, got %d", cfg.App.Port)
	}

	if cfg.Cache.Mode != CacheModeNone {
		t.Error("Expected cache disabled")
	}

	if cfg.Cache.TTL != 10*time.Minute {
		t.Errorf("Expected cache TTL '10m', got '%v'", cfg.Cache.TTL)
	}
}

func TestConfig_LoadFromEnv_InvalidPort(t *testing.T) {
	clearEnv()
	resetFlags()

	os.Setenv("CHECKS_PORT", ":3000")
	defer clearEnv()

	_, err := Load()
	if err == nil {
		t.Error("Expected error for invalid port value")
	}
}

func TestConfig_LoadFromEnv_InvalidMode(t *testing.T) {
	clearEnv()
	resetFlags()

	os.Setenv("CHECKS_CACHE_MODE", "maybe")
	defer clearEnv()

	_, err := Load()
	if err == nil {
		t.Error("Expected error for invalid mode value")
	}
}

func TestConfig_LoadFromEnv_InvalidDuration(t *testing.T) {
	clearEnv()
	resetFlags()

	os.Setenv("CHECKS_CACHE_TTL", "invalid")
	defer clearEnv()

	_, err := Load()
	if err == nil {
		t.Error("Expected error for invalid duration value")
	}
}

func TestConfig_Validate_EmptyAdvertisedAddress(t *testing.T) {
	cfg := &Config{
		App: AppConfig{
			Host:              "0.0.0.0",
			Port:              8080,
			AdvertisedAddress: "",
		},
		Cache: CacheConfig{
			Mode: CacheModeMem,
			TTL:  5 * time.Minute,
		},
	}

	err := cfg.validate()
	if err == nil {
		t.Error("Expected validation error for empty advertised address")
	}
}

func TestConfig_Validate_InvalidPort(t *testing.T) {
	cfg := &Config{
		App: AppConfig{
			Host:              "0.0.0.0",
			Port:              70000,
			AdvertisedAddress: "http://test.com",
		},
		Cache: CacheConfig{
			Mode: CacheModeMem,
			TTL:  5 * time.Minute,
		},
	}

	err := cfg.validate()
	if err == nil {
		t.Error("Expected validation error for invalid port")
	}
}

func TestConfig_Validate_NegativeTTL(t *testing.T) {
	cfg := &Config{
		App: AppConfig{
			Host:              "0.0.0.0",
			Port:              8080,
			AdvertisedAddress: "http://test.com",
		},
		Cache: CacheConfig{
			Mode: CacheModeMem,
			TTL:  -1 * time.Minute,
		},
	}

	err := cfg.validate()
	if err == nil {
		t.Error("Expected validation error for negative TTL")
	}
}

func TestConfig_Validate_ZeroTTLWithCacheEnabled(t *testing.T) {
	cfg := &Config{
		App: AppConfig{
			Host:              "0.0.0.0",
			Port:              8080,
			AdvertisedAddress: "http://test.com",
		},
		Cache: CacheConfig{
			Mode: CacheModeMem,
			TTL:  0,
		},
	}

	err := cfg.validate()
	if err == nil {
		t.Error("Expected validation error for zero TTL with cache enabled")
	}
}

func TestConfig_Validate_ZeroTTLWithCacheDisabled(t *testing.T) {
	cfg := &Config{
		App: AppConfig{
			Host:              "0.0.0.0",
			Port:              8080,
			AdvertisedAddress: "http://test.com",
		},
		Cache: CacheConfig{
			Mode: CacheModeNone,
			TTL:  0,
		},
	}

	err := cfg.validate()
	if err != nil {
		t.Errorf("Expected no validation error for zero TTL with cache disabled, got: %v", err)
	}
}

func TestConfig_String(t *testing.T) {
	cfg := &Config{
		App: AppConfig{
			Host:              "0.0.0.0",
			Port:              8080,
			AdvertisedAddress: "http://test-app.com",
		},
		Cache: CacheConfig{
			Mode: CacheModeMem,
			TTL:  5 * time.Minute,
		},
	}

	str := cfg.String()
	expected := "Config{App: {Host: 0.0.0.0, Port: 8080, AdvertisedAddress: http://test-app.com}, Cache: {Mode: mem, TTL: 5m0s}}"
	if str != expected {
		t.Errorf("Expected string '%s', got '%s'", expected, str)
	}
}

// Helper functions

func clearEnv() {
	envVars := []string{
		"CHECKS_ADVERTISED_ADDRESS",
		"CHECKS_HOST",
		"CHECKS_PORT",
		"CHECKS_CACHE_MODE",
		"CHECKS_CACHE_TTL",
	}

	for _, env := range envVars {
		os.Unsetenv(env)
	}
}

func resetFlags() {
	// Reset the flag package state
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
}
