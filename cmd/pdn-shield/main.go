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

// Log field and strategy names.
const (
	logErr            = "err"
	strategyPartial   = "partial"
	strategyFull      = "full"
	strategyToken     = "token"
	strategySynthetic = "synthetic"
	storeRedis        = "redis"
)

func main() {
	configPath := flag.String("config", "configs/config.yaml", "path to config file")
	flag.Parse()

	if env := os.Getenv("PDN_CONFIG"); env != "" {
		*configPath = env
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("config load failed", logErr, err)
		os.Exit(1)
	}

	logger := newLogger(cfg.Logging.Level, cfg.Logging.Format)
	slog.SetDefault(logger)

	key := loadEncryptionKey(cfg, logger)
	st, closeStore := newStore(cfg, key, logger)
	defer closeStore()

	// Pipeline and engine.
	pipeline := pii.NewPipeline(detectors.Default()...)
	strategies := map[string]mask.Strategy{
		strategyPartial:   mask.MustPartial(),
		strategyFull:      mask.NewFull(),
		strategyToken:     mask.NewToken(),
		strategySynthetic: mask.NewSynthetic(),
	}
	eng := engine.New(pipeline, st, strategies)

	// Metrics and HTTP server.
	m := metrics.New()
	srv := httpapi.New(cfg, eng, st, m, logger)
	httpServer := newHTTPServer(cfg, srv)

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
			logger.Error("http server failed", logErr, err)
			os.Exit(1)
		}
	}()

	<-stop
	logger.Info("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		logger.Error("shutdown failed", logErr, err)
	}
	logger.Info("stopped")
}

// loadEncryptionKey reads the encryption key from the configured environment
// variable, exiting on failure.
func loadEncryptionKey(cfg *config.Config, logger *slog.Logger) []byte {
	keyEnv := cfg.Store.EncryptionKeyEnv
	if keyEnv == "" {
		keyEnv = "PDN_ENC_KEY"
	}
	key, err := crypto.KeyFromEnv(keyEnv)
	if err != nil {
		logger.Error("encryption key load failed", logErr, err)
		os.Exit(1)
	}
	return key
}

// newStore builds the configured store backend, exiting on failure. It returns
// the store and a cleanup function that closes the underlying backend.
func newStore(cfg *config.Config, key []byte, logger *slog.Logger) (store.Store, func()) {
	switch cfg.Store.Kind {
	case storeRedis:
		return newRedisStore(cfg, key, logger)
	default:
		return newMemoryStore(key, logger)
	}
}

// newRedisStore builds a Redis-backed store, exiting on failure.
func newRedisStore(cfg *config.Config, key []byte, logger *slog.Logger) (store.Store, func()) {
	password := os.Getenv("PDN_REDIS_PASSWORD")
	rs, err := store.NewRedisWithOptions(cfg.Store.RedisAddr, password, key, store.Options{
		PoolSize: cfg.Store.RedisPool,
		Wait:     cfg.Store.RedisWait,
		Timeout:  cfg.Store.RedisTimeout,
	})
	if err != nil {
		logger.Error("redis store init failed", logErr, err)
		os.Exit(1)
	}
	return rs, rs.Close
}

// newMemoryStore builds an in-memory store, exiting on failure.
func newMemoryStore(key []byte, logger *slog.Logger) (store.Store, func()) {
	ms, err := store.NewMemory(key)
	if err != nil {
		logger.Error("memory store init failed", logErr, err)
		os.Exit(1)
	}
	return ms, ms.Close
}

// newHTTPServer builds the HTTP server from the config and handler.
func newHTTPServer(cfg *config.Config, srv *httpapi.Server) *http.Server {
	return &http.Server{
		Addr:         cfg.Server.Addr,
		Handler:      srv.Handler(),
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}
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
