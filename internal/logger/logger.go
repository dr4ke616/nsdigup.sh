package logger

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
)

var defaultLogger *slog.Logger

// Init initializes the global logger with the specified level and format
func Init(level, format string) (*slog.Logger, error) {
	// Parse log level
	var slogLevel slog.Level
	switch strings.ToLower(level) {
	case "debug":
		slogLevel = slog.LevelDebug
	case "info":
		slogLevel = slog.LevelInfo
	case "warn":
		slogLevel = slog.LevelWarn
	case "error":
		slogLevel = slog.LevelError
	default:
		return nil, fmt.Errorf("invalid log level '%s': must be debug, info, warn, or error", level)
	}

	// Create handler options
	opts := &slog.HandlerOptions{
		Level: slogLevel,
	}

	// Create handler based on format
	var handler slog.Handler
	switch strings.ToLower(format) {
	case "text":
		handler = slog.NewTextHandler(os.Stdout, opts)
	case "json":
		handler = slog.NewJSONHandler(os.Stdout, opts)
	default:
		return nil, fmt.Errorf("invalid log format '%s': must be text or json", format)
	}

	// Create and set the default logger
	defaultLogger = slog.New(handler)

	return defaultLogger, nil
}

// Get returns the global logger instance
func Get() *slog.Logger {
	if defaultLogger == nil {
		// Fallback to default logger if Init wasn't called
		defaultLogger = slog.Default()
	}
	return defaultLogger
}

// ContextKey is an unexported type to prevent collisions with context keys from other packages
type ContextKey string

// LoggerContextKey is the context key used to store the logger in request contexts
const LoggerContextKey ContextKey = "logger"

// GetFromContext retrieves the logger from the context.
// If no logger is found in the context, it returns the provided fallback logger.
func GetFromContext(ctx context.Context, fallback *slog.Logger) *slog.Logger {
	if logger, ok := ctx.Value(LoggerContextKey).(*slog.Logger); ok {
		return logger
	}
	return fallback
}
