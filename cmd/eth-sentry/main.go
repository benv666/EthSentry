package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"eth-sentry/internal/config"
	"eth-sentry/internal/monitor"
	"eth-sentry/internal/notifications"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("Failed to load configuration", "error", err)
		os.Exit(1)
	}

	if len(cfg.ValidatorIndices) == 0 {
		slog.Warn("No validator indices configured. Only checking node sync status.")
	}

	// Setup structured logging
	opts := &slog.HandlerOptions{
		AddSource: true,
		Level:     slog.LevelDebug,
	}
	handler := slog.NewTextHandler(os.Stdout, opts)
	logger := slog.New(handler)

	// Initialize notification system
	notifier := notifications.New(&cfg, logger)

	// Initialize monitor
	mon := monitor.New(&cfg, notifier, logger)

	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		logger.Info("Received shutdown signal, initiating graceful shutdown...")
		cancel()
	}()

	mon.Start(ctx)
}
