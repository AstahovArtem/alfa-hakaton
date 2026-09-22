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

// Route names.
const (
	routeProcess = "process"
	routeMask    = "mask"
	routeUnmask  = "unmask"
	routeChat    = "chat"
	routeHealthz = "healthz"
	routeReadyz  = "readyz"
)

// JSON and log field names.
const (
	fieldStatus       = "status"
	fieldStore        = "store"
	fieldStoreOK      = "store_ok"
	fieldSystem       = "system"
	fieldRoute        = "route"
	fieldPayloadID    = "payload_id"
	fieldMisses       = "misses"
	fieldError        = "error"
	fieldErr          = "err"
	contentTypeJSON   = "application/json; charset=utf-8"
	headerContentType = "Content-Type"
)

// Request direction and store operation names.
const (
	dirMask   = "mask"
	dirUnmask = "unmask"
	opLoad    = "load"
)

// Default masking strategy.
const strategyPartial = "partial"

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
	mux.HandleFunc("POST /process", s.wrap(s.handleProcess, routeProcess))
	mux.HandleFunc("POST /mask", s.wrap(s.handleMask, routeMask))
	mux.HandleFunc("POST /unmask", s.wrap(s.handleUnmask, routeUnmask))
	mux.HandleFunc("POST /v1/chat/completions", s.wrap(s.handleChat, routeChat))
	mux.HandleFunc("GET /healthz", s.wrap(s.handleHealthz, routeHealthz))
	mux.HandleFunc("GET /readyz", s.wrap(s.handleReadyz, routeReadyz))
	mux.HandleFunc("GET /metrics", promhttp.HandlerFor(s.metrics.Registry, promhttp.HandlerOpts{}).ServeHTTP)
	mux.HandleFunc("GET /", s.handleIndex)
	return mux
}

// wrap applies backpressure, metrics and request logging around a handler.
func (s *Server) wrap(h http.HandlerFunc, route string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		if !s.acquireSlot(w) {
			return
		}
		s.applyBodyLimit(w, r)

		// Identify the system. /process allows the default system; health
		// endpoints are public.
		allowDefault := route == routeProcess
		public := route == routeHealthz || route == routeReadyz
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

		s.logRequest(route, start, sw, auth, info)
	}
}

// acquireSlot applies backpressure by acquiring the inflight slot, returning
// false (and writing a 429) when the slot is unavailable.
func (s *Server) acquireSlot(w http.ResponseWriter) bool {
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	default:
		s.metrics.Rejected.WithLabelValues("inflight").Inc()
		w.Header().Set("Retry-After", "1")
		writeError(w, http.StatusTooManyRequests, "too many requests")
		return false
	}
	s.metrics.Inflight.Inc()
	defer s.metrics.Inflight.Dec()
	return true
}

// applyBodyLimit wraps the request body with a size limit when configured.
func (s *Server) applyBodyLimit(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Server.MaxBodyBytes > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, s.cfg.Server.MaxBodyBytes)
	}
}

// logRequest emits one log line per request, never with PII values or span text.
func (s *Server) logRequest(route string, start time.Time, sw *statusWriter, auth authResult, info *reqInfo) {
	dur := time.Since(start)
	systemID := "public"
	if auth.system != nil {
		systemID = auth.system.ID
	}
	s.metrics.RequestsTotal.WithLabelValues(route, systemID, strconv.Itoa(sw.status)).Inc()
	s.metrics.RequestDuration.WithLabelValues(route).Observe(dur.Seconds())

	attrs := []any{
		fieldSystem, systemID,
		fieldRoute, route,
		"direction", info.direction,
		fieldStatus, sw.status,
		"duration_ms", dur.Milliseconds(),
	}
	if info.payloadID != "" {
		attrs = append(attrs, fieldPayloadID, info.payloadID)
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
		attrs = append(attrs, fieldMisses, info.misses)
	}
	attrs = append(attrs, "detect_ms", info.stages.DetectMs)
	attrs = append(attrs, "mask_ms", info.stages.MaskMs)
	attrs = append(attrs, "store_ms", info.stages.StoreMs)
	if info.stages.LLMMs > 0 {
		attrs = append(attrs, "llm_ms", info.stages.LLMMs)
	}
	s.logger.Info("request", attrs...)
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
	w.Header().Set(headerContentType, contentTypeJSON)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{fieldError: msg})
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
	w.Header().Set(headerContentType, "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

// handleHealthz reports liveness.
func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		fieldStatus:  "ok",
		fieldStore:   s.cfg.Store.Kind,
		fieldStoreOK: true,
	})
}

// handleReadyz reports readiness based on store availability.
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 500*time.Millisecond)
	defer cancel()
	if err := s.store.Ping(ctx); err != nil {
		s.metrics.StoreErrors.WithLabelValues("ping").Inc()
		writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			fieldStatus:  "unavailable",
			fieldStore:   s.cfg.Store.Kind,
			fieldStoreOK: false,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		fieldStatus:  "ok",
		fieldStore:   s.cfg.Store.Kind,
		fieldStoreOK: true,
	})
}

// storeUnavailable reports a store error as a 503.
func (s *Server) storeUnavailable(w http.ResponseWriter, op string, err error) {
	s.metrics.StoreErrors.WithLabelValues(op).Inc()
	s.logger.Error("store error", "op", op, fieldErr, err)
	writeError(w, http.StatusServiceUnavailable, "store unavailable")
}

// isStoreError reports whether err is a store-level failure.
func isStoreError(err error) bool {
	return err != nil && !errors.Is(err, engine.ErrNotFound)
}
