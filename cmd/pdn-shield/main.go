package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"pdn-shield/internal/config"
	"pdn-shield/internal/crypto"
	"pdn-shield/internal/engine"
	"pdn-shield/internal/httpapi"
	"pdn-shield/internal/mask"
	"pdn-shield/internal/metrics"
	"pdn-shield/internal/pii"
	"pdn-shield/internal/pii/detectors"
	"pdn-shield/internal/store"
)

// version is set at build time via -ldflags.
var version = "dev"

func main() {
	configPath := flag.String("config", "configs/config.yaml", "path to config file")
	flag.Parse()

	if env := os.Getenv("PDN_CONFIG"); env != "" {
		*configPath = env
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("config load failed", "err", err)
		os.Exit(1)
	}

	logger := newLogger(cfg.Logging.Level, cfg.Logging.Format)
	slog.SetDefault(logger)

	// Encryption key.
	keyEnv := cfg.Store.EncryptionKeyEnv
	if keyEnv == "" {
		keyEnv = "PDN_ENC_KEY"
	}
	key, err := crypto.KeyFromEnv(keyEnv)
	if err != nil {
		logger.Error("encryption key load failed", "err", err)
		os.Exit(1)
	}

	// Store.
	var st store.Store
	switch cfg.Store.Kind {
	case "redis":
		password := os.Getenv("PDN_REDIS_PASSWORD")
		rs, err := store.NewRedisWithOptions(cfg.Store.RedisAddr, password, key, store.Options{
			PoolSize: cfg.Store.RedisPool,
			Wait:     cfg.Store.RedisWait,
			Timeout:  cfg.Store.RedisTimeout,
		})
		if err != nil {
			logger.Error("redis store init failed", "err", err)
			os.Exit(1)
		}
		defer rs.Close()
		st = rs
	default:
		ms, err := store.NewMemory(key)
		if err != nil {
			logger.Error("memory store init failed", "err", err)
			os.Exit(1)
		}
		defer ms.Close()
		st = ms
	}

	// Pipeline and engine.
	pipeline := pii.NewPipeline(detectors.Default()...)
	strategies := map[string]mask.Strategy{
		"partial":   mask.MustPartial(),
		"full":      mask.NewFull(),
		"token":     mask.NewToken(),
		"synthetic": mask.NewSynthetic(),
	}
	eng := engine.New(pipeline, st, strategies)

	// Metrics and HTTP server.
	m := metrics.New()
	srv := httpapi.New(cfg, eng, st, m, logger)
	httpServer := &http.Server{
		Addr:         cfg.Server.Addr,
		Handler:      srv.Handler(),
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	logger.Info("starting pdn-shield",
		"version", version,
		"addr", cfg.Server.Addr,
		"store", cfg.Store.Kind,
		"systems", len(cfg.Systems),
		"detectors", len(detectors.Default()),
		"rules", ruleCount(),
	)

	// Graceful shutdown on SIGTERM/SIGINT.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("http server failed", "err", err)
			os.Exit(1)
		}
	}()

	<-stop
	logger.Info("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		logger.Error("shutdown failed", "err", err)
	}
	logger.Info("stopped")
}

// newLogger builds a slog logger in text or json format.
func newLogger(level, format string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: lvl}
	if format == "json" {
		return slog.New(slog.NewJSONHandler(os.Stdout, opts))
	}
	return slog.New(slog.NewTextHandler(os.Stdout, opts))
}

// ruleCount returns the number of regex rules for the startup log.
func ruleCount() int {
	rules, err := detectors.DefaultRules()
	if err != nil {
		return 0
	}
	return len(rules)
}
