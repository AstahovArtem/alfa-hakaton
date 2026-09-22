// Package httpapi exposes the pdn-shield HTTP service.
package httpapi

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"pdn-shield/internal/config"
	"pdn-shield/internal/engine"
	"pdn-shield/internal/metrics"
	"pdn-shield/internal/store"
)

//go:embed static/index.html
var staticFS embed.FS

// Server is the HTTP service.
type Server struct {
	cfg     *config.Config
	engine  *engine.Engine
	store   store.Store
	metrics *metrics.Metrics
	logger  *slog.Logger
	llm     *LLMClient
	sem     chan struct{}
}

// New builds a Server.
func New(cfg *config.Config, eng *engine.Engine, st store.Store, m *metrics.Metrics, logger *slog.Logger) *Server {
	s := &Server{
		cfg:     cfg,
		engine:  eng,
		store:   st,
		metrics: m,
		logger:  logger,
		sem:     make(chan struct{}, cfg.Server.MaxInflight),
	}
	s.llm = NewLLMClient(cfg.LLM, logger, m)
	return s
}

// Handler returns the root http.Handler with all routes registered.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /process", s.wrap(s.handleProcess, "process"))
	mux.HandleFunc("POST /mask", s.wrap(s.handleMask, "mask"))
	mux.HandleFunc("POST /unmask", s.wrap(s.handleUnmask, "unmask"))
	mux.HandleFunc("POST /v1/chat/completions", s.wrap(s.handleChat, "chat"))
	mux.HandleFunc("GET /healthz", s.wrap(s.handleHealthz, "healthz"))
	mux.HandleFunc("GET /readyz", s.wrap(s.handleReadyz, "readyz"))
	mux.HandleFunc("GET /metrics", promhttp.HandlerFor(s.metrics.Registry, promhttp.HandlerOpts{}).ServeHTTP)
	mux.HandleFunc("GET /", s.handleIndex)
	return mux
}

// wrap applies backpressure, metrics and request logging around a handler.
func (s *Server) wrap(h http.HandlerFunc, route string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Backpressure: acquire the inflight slot.
		select {
		case s.sem <- struct{}{}:
			defer func() { <-s.sem }()
		default:
			s.metrics.Rejected.WithLabelValues("inflight").Inc()
			w.Header().Set("Retry-After", "1")
			writeError(w, http.StatusTooManyRequests, "too many requests")
			return
		}
		s.metrics.Inflight.Inc()
		defer s.metrics.Inflight.Dec()

		// Body size limit.
		if s.cfg.Server.MaxBodyBytes > 0 {
			r.Body = http.MaxBytesReader(w, r.Body, s.cfg.Server.MaxBodyBytes)
		}

		// Identify the system. /process allows the default system; health
		// endpoints are public.
		allowDefault := route == "process"
		public := route == "healthz" || route == "readyz"
		var auth authResult
		if !public {
			auth = s.authenticate(r, allowDefault)
			if auth.status != 0 {
				s.metrics.RequestsTotal.WithLabelValues(route, "unknown", strconv.Itoa(auth.status)).Inc()
				s.metrics.Rejected.WithLabelValues("auth").Inc()
				writeError(w, auth.status, "system not allowed")
				return
			}
		}

		// Wrap the response writer to capture the status code.
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}

		// Attach the per-request log info so handlers can record payload id,
		// direction, counts and stage timings.
		ctx, info := withReqInfo(r.Context())
		h(sw, r.WithContext(ctx))

		dur := time.Since(start)
		systemID := "public"
		if auth.system != nil {
			systemID = auth.system.ID
		}
		s.metrics.RequestsTotal.WithLabelValues(route, systemID, strconv.Itoa(sw.status)).Inc()
		s.metrics.RequestDuration.WithLabelValues(route).Observe(dur.Seconds())

		// One log line per request, never with PII values or span text.
		attrs := []any{
			"system", systemID,
			"route", route,
			"direction", info.direction,
			"status", sw.status,
			"duration_ms", dur.Milliseconds(),
		}
		if info.payloadID != "" {
			attrs = append(attrs, "payload_id", info.payloadID)
		}
		if info.textLen > 0 {
			attrs = append(attrs, "text_len", info.textLen)
		}
		if info.chunks > 0 {
			attrs = append(attrs, "chunks", info.chunks)
		}
		if len(info.found) > 0 {
			attrs = append(attrs, "found", categoryMap(info.found))
		}
		if info.misses > 0 {
			attrs = append(attrs, "misses", info.misses)
		}
		if info.stages.DetectMs > 0 {
			attrs = append(attrs, "detect_ms", info.stages.DetectMs)
		}
		if info.stages.MaskMs > 0 {
			attrs = append(attrs, "mask_ms", info.stages.MaskMs)
		}
		if info.stages.StoreMs > 0 {
			attrs = append(attrs, "store_ms", info.stages.StoreMs)
		}
		if info.stages.LLMMs > 0 {
			attrs = append(attrs, "llm_ms", info.stages.LLMMs)
		}
		s.logger.Info("request", attrs...)
	}
}

// statusWriter captures the response status code.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// writeJSON writes a JSON response with the correct content type.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// readJSON decodes a JSON request body, returning a 400 on malformed input and
// a 413 when the body exceeds the configured limit.
func readJSON(w http.ResponseWriter, r *http.Request, v interface{}) error {
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return err
		}
		writeError(w, http.StatusBadRequest, "invalid json")
		return err
	}
	return nil
}

// handleIndex serves the embedded demo page.
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data, err := staticFS.ReadFile("static/index.html")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "demo page unavailable")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

// handleHealthz reports liveness.
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":   "ok",
		"store":    s.cfg.Store.Kind,
		"store_ok": true,
	})
}

// handleReadyz reports readiness based on store availability.
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 500*time.Millisecond)
	defer cancel()
	if err := s.store.Ping(ctx); err != nil {
		s.metrics.StoreErrors.WithLabelValues("ping").Inc()
		writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"status":   "unavailable",
			"store":    s.cfg.Store.Kind,
			"store_ok": false,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":   "ok",
		"store":    s.cfg.Store.Kind,
		"store_ok": true,
	})
}

// storeUnavailable reports a store error as a 503.
func (s *Server) storeUnavailable(w http.ResponseWriter, op string, err error) {
	s.metrics.StoreErrors.WithLabelValues(op).Inc()
	s.logger.Error("store error", "op", op, "err", err)
	writeError(w, http.StatusServiceUnavailable, "store unavailable")
}

// isStoreError reports whether err is a store-level failure.
func isStoreError(err error) bool {
	return err != nil && !errors.Is(err, engine.ErrNotFound)
}
