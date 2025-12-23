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
	if cfg.App.Name != "checks.sh" {
		t.Errorf("Expected app name 'checks.sh', got '%s'", cfg.App.Name)
	}

	if cfg.App.Port != ":8080" {
		t.Errorf("Expected port ':8080', got '%s'", cfg.App.Port)
	}

	if !cfg.Cache.Enabled {
		t.Error("Expected cache enabled by default")
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
	os.Setenv("CHECKS_APP_NAME", "test-app")
	os.Setenv("CHECKS_PORT", "9090")
	os.Setenv("CHECKS_CACHE_ENABLED", "false")
	os.Setenv("CHECKS_CACHE_TTL", "10m")
	defer clearEnv()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if cfg.App.Name != "test-app" {
		t.Errorf("Expected app name 'test-app', got '%s'", cfg.App.Name)
	}

	if cfg.App.Port != ":9090" {
		t.Errorf("Expected port ':9090', got '%s'", cfg.App.Port)
	}

	if cfg.Cache.Enabled {
		t.Error("Expected cache disabled")
	}

	if cfg.Cache.TTL != 10*time.Minute {
		t.Errorf("Expected cache TTL '10m', got '%v'", cfg.Cache.TTL)
	}
}

func TestConfig_LoadFromEnv_PortWithColon(t *testing.T) {
	clearEnv()
	resetFlags()

	os.Setenv("CHECKS_PORT", ":3000")
	defer clearEnv()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if cfg.App.Port != ":3000" {
		t.Errorf("Expected port ':3000', got '%s'", cfg.App.Port)
	}
}

func TestConfig_LoadFromEnv_InvalidBool(t *testing.T) {
	clearEnv()
	resetFlags()

	os.Setenv("CHECKS_CACHE_ENABLED", "maybe")
	defer clearEnv()

	_, err := Load()
	if err == nil {
		t.Error("Expected error for invalid boolean value")
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

func TestConfig_Validate_EmptyAppName(t *testing.T) {
	cfg := &Config{
		App: AppConfig{
			Name: "",
			Port: ":8080",
		},
		Cache: CacheConfig{
			Enabled: true,
			TTL:     5 * time.Minute,
		},
	}

	err := cfg.validate()
	if err == nil {
		t.Error("Expected validation error for empty app name")
	}
}

func TestConfig_Validate_EmptyPort(t *testing.T) {
	cfg := &Config{
		App: AppConfig{
			Name: "test",
			Port: "",
		},
		Cache: CacheConfig{
			Enabled: true,
			TTL:     5 * time.Minute,
		},
	}

	err := cfg.validate()
	if err == nil {
		t.Error("Expected validation error for empty port")
	}
}

func TestConfig_Validate_NegativeTTL(t *testing.T) {
	cfg := &Config{
		App: AppConfig{
			Name: "test",
			Port: ":8080",
		},
		Cache: CacheConfig{
			Enabled: true,
			TTL:     -1 * time.Minute,
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
			Name: "test",
			Port: ":8080",
		},
		Cache: CacheConfig{
			Enabled: true,
			TTL:     0,
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
			Name: "test",
			Port: ":8080",
		},
		Cache: CacheConfig{
			Enabled: false,
			TTL:     0,
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
			Name: "test-app",
			Port: ":8080",
		},
		Cache: CacheConfig{
			Enabled: true,
			TTL:     5 * time.Minute,
		},
	}

	str := cfg.String()
	expected := "Config{App: {Name: test-app, Port: :8080}, Cache: {Enabled: true, TTL: 5m0s}}"
	if str != expected {
		t.Errorf("Expected string '%s', got '%s'", expected, str)
	}
}

// Helper functions

func clearEnv() {
	envVars := []string{
		"CHECKS_APP_NAME",
		"CHECKS_PORT",
		"CHECKS_CACHE_ENABLED",
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
