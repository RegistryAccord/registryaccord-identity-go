// cmd/identityd/main.go
package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/RegistryAccord/registryaccord-identity-go/internal/config"
	"github.com/RegistryAccord/registryaccord-identity-go/internal/server"
	"github.com/RegistryAccord/registryaccord-identity-go/internal/storage"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config load failed: %v\n", err)
		os.Exit(1)
	}

	// Set up structured logging
	logLevel := slog.LevelInfo
	if cfg.Env == "dev" {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))
	slog.SetDefault(logger)

	var store storage.ExtendedStore
	if cfg.DatabaseDSN != "" {
		store, err = storage.NewPostgres(cfg.DatabaseDSN)
		if err != nil {
			logger.Error("postgres init failed", "error", err)
			os.Exit(1)
		}
		if err := storage.MigratePostgres(context.Background(), store.(interface{ DB() *sql.DB }).DB()); err != nil {
			logger.Error("postgres migration failed", "error", err)
			os.Exit(1)
		}
	} else {
		store = storage.NewMemory()
	}

	handler, err := server.New(cfg, store, logger)
	if err != nil {
		logger.Error("server init failed", "error", err)
		os.Exit(1)
	}

	// Use the Port from config if Address is not set or is default
	addr := cfg.Address
	if addr == "" || addr == ":8080" {
		addr = ":" + strconv.Itoa(cfg.Port)
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           handler.Router(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	// Start HTTP server
	// Create stop channel for graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		logger.Info("identityd starting", "addr", srv.Addr, "env", cfg.Env, "didMethod", cfg.DIDMethod)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	// Start metrics server if configured
	if cfg.MetricsAddress != "" && cfg.MetricsAddress != cfg.Address {
		metricsMux := http.NewServeMux()
		metricsMux.Handle("/metrics", server.NewMetricsHandler())
		metricsSrv := &http.Server{
			Addr:              cfg.MetricsAddress,
			Handler:           metricsMux,
			ReadHeaderTimeout: 5 * time.Second,
		}
		go func() {
			logger.Info("metrics server starting", "addr", metricsSrv.Addr)
			if err := metricsSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Error("metrics server error", "error", err)
			}
		}()
	}

	// Start background cleanup job for expired nonces
	// This periodic job removes expired nonces from storage to prevent
	// database bloat and ensure the single-use nature of nonces
	if cfg.DatabaseDSN != "" {
		go func() {
			ticker := time.NewTicker(1 * time.Hour)
			defer ticker.Stop()

			for {
				select {
				case <-ticker.C:
					ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
					if err := store.CleanupExpired(ctx, time.Now().UTC()); err != nil {
						logger.Error("cleanup expired nonces failed", "error", err)
					}
					// Also cleanup expired recovery tokens
					if err := store.CleanupExpiredRecoveryTokens(ctx, time.Now().UTC()); err != nil {
						logger.Error("cleanup expired recovery tokens failed", "error", err)
					}
					cancel()
				case <-stop:
					return
				}
			}
		}()
	}

	<-stop

	logger.Info("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
		os.Exit(1)
	}
	logger.Info("shutdown complete")
}
