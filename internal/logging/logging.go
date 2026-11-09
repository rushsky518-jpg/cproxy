// Package logging builds the process-wide structured logger.
package logging

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
)

// New creates a text or JSON logger.
func New(level, format string) (*slog.Logger, error) {
	var lv slog.Level
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "", "info":
		lv = slog.LevelInfo
	case "debug":
		lv = slog.LevelDebug
	case "warn", "warning":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		return nil, fmt.Errorf("unsupported log_level %q", level)
	}

	opts := &slog.HandlerOptions{Level: lv}
	var h slog.Handler
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "text":
		h = slog.NewTextHandler(os.Stdout, opts)
	case "json":
		h = slog.NewJSONHandler(os.Stdout, opts)
	default:
		return nil, fmt.Errorf("unsupported log_format %q", format)
	}
	return slog.New(h), nil
}
