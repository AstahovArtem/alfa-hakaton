// Package httpapi exposes the pdn-shield HTTP service.
package httpapi

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"io"
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

// maxPayloadIDBytes bounds any caller-supplied id (payload_id, /mask id,
// /unmask id) so an oversized id cannot be used to pad requests or abuse the
// store.
const maxPayloadIDBytes = 256

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

// Handler returns the root http.Handler with all routes registered. When
// server.metrics_addr is set, /metrics is served only on the separate
// listener started by main.go (see MetricsHandler) and left off this mux;
// when it is empty, /metrics stays here for backward compatibility.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /process", s.wrap(s.handleProcess, routeProcess))
	mux.HandleFunc("POST /mask", s.wrap(s.handleMask, routeMask))
	mux.HandleFunc("POST /unmask", s.wrap(s.handleUnmask, routeUnmask))
	mux.HandleFunc("POST /v1/chat/completions", s.wrap(s.handleChat, routeChat))
	mux.HandleFunc("GET /healthz", s.wrap(s.handleHealthz, routeHealthz))
	mux.HandleFunc("GET /readyz", s.wrap(s.handleReadyz, routeReadyz))
	if s.cfg.Server.MetricsAddr == "" {
		mux.Handle("GET /metrics", s.MetricsHandler())
	}
	mux.HandleFunc("GET /", s.handleIndex)
	return mux
}

// MetricsHandler returns the standalone /metrics handler, for either the main
// mux (when server.metrics_addr is empty) or a separate listener (when it is
// set; see cmd/pdn-shield/main.go).
func (s *Server) MetricsHandler() http.Handler {
	return promhttp.HandlerFor(s.metrics.Registry, promhttp.HandlerOpts{})
}

// wrap applies backpressure, metrics and request logging around a handler.
// Every outcome -- a 429 from backpressure, a 401/403 from auth, or the
// handler's own response -- goes through the same request-log line and the
// same RequestsTotal counter, so no rejected request is invisible in metrics
// or logs.
func (s *Server) wrap(h http.HandlerFunc, route string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}

		// Attach the per-request log info so handlers can record payload id,
		// direction, counts and stage timings.
		ctx, info := withReqInfo(r.Context())
		r = r.WithContext(ctx)

		release, acquired := s.acquireSlot(sw)
		if !acquired {
			s.logRequest(route, start, sw, authResult{}, info)
			return
		}
		defer release()

		s.applyBodyLimit(sw, r)

		// Identify the system. /process allows the default system; health
		// endpoints are public.
		public := route == routeHealthz || route == routeReadyz
		var auth authResult
		if !public {
			auth = s.authenticate(r, route)
			if auth.status != 0 {
				s.metrics.Rejected.WithLabelValues("auth").Inc()
				writeError(sw, auth.status, "system not allowed")
				s.logRequest(route, start, sw, auth, info)
				return
			}
			r = r.WithContext(withSystem(r.Context(), auth.system))
		}

		h(sw, r)

		s.logRequest(route, start, sw, auth, info)
	}
}

// acquireSlot applies backpressure by acquiring the inflight slot. On success
// it returns a release function the caller must defer for the lifetime of
// the whole request (not just this call) so the slot and the Inflight gauge
// stay held until the handler has actually finished, and true. On failure it
// writes a 429 with Retry-After and returns a no-op release and false.
func (s *Server) acquireSlot(w http.ResponseWriter) (release func(), acquired bool) {
	select {
	case s.sem <- struct{}{}:
		s.metrics.Inflight.Inc()
		return func() {
			s.metrics.Inflight.Dec()
			<-s.sem
		}, true
	default:
		s.metrics.Rejected.WithLabelValues("inflight").Inc()
		w.Header().Set("Retry-After", "1")
		writeError(w, http.StatusTooManyRequests, "too many requests")
		return func() {}, false
	}
}

// applyBodyLimit wraps the request body with a size limit when configured.
func (s *Server) applyBodyLimit(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Server.MaxBodyBytes > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, s.cfg.Server.MaxBodyBytes)
	}
}

// logRequest emits one log line per request, never with PII values, span text
// or the raw payload id (only a short HMAC of it, safe to correlate without
// revealing the id itself).
func (s *Server) logRequest(route string, start time.Time, sw *statusWriter, auth authResult, info *reqInfo) {
	dur := time.Since(start)
	systemID := systemLabel(route, auth)
	s.metrics.RequestsTotal.WithLabelValues(route, systemID, strconv.Itoa(sw.status)).Inc()
	s.metrics.RequestDuration.WithLabelValues(route).Observe(dur.Seconds())
	if info.tokens > 0 {
		s.metrics.Tokens.WithLabelValues(route).Add(float64(info.tokens))
	}

	attrs := []any{
		fieldSystem, systemID,
		fieldRoute, route,
		"direction", info.direction,
		fieldStatus, sw.status,
		"duration_ms", dur.Milliseconds(),
	}
	if info.payloadID != "" {
		attrs = append(attrs, fieldPayloadID, s.store.HashID(info.payloadID))
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
	if info.tokens > 0 {
		attrs = append(attrs, "tokens", info.tokens)
	}
	attrs = append(attrs, "detect_ms", info.stages.DetectMs)
	attrs = append(attrs, "mask_ms", info.stages.MaskMs)
	attrs = append(attrs, "store_ms", info.stages.StoreMs)
	if info.stages.LLMMs > 0 {
		attrs = append(attrs, "llm_ms", info.stages.LLMMs)
	}
	s.logger.Info("request", attrs...)
}

// systemLabel returns the metric/log label for the resolved system: its id
// when authenticated, "public" for the unauthenticated health routes, or
// "unknown" when the request was rejected before a system could be resolved
// (backpressure or a failed authentication).
func systemLabel(route string, auth authResult) string {
	if auth.system != nil {
		return auth.system.ID
	}
	if route == routeHealthz || route == routeReadyz {
		return "public"
	}
	return "unknown"
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

// readJSON decodes a JSON request body, returning a 400 on malformed input, a
// 413 when the body exceeds the configured limit, and a 400 when there is any
// non-whitespace data after the JSON value (e.g. a second smuggled object).
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
	if _, err := dec.Token(); err != io.EOF {
		writeError(w, http.StatusBadRequest, "trailing data after JSON body")
		return errors.New("httpapi: trailing data after JSON body")
	}
	return nil
}

// validPayloadID reports whether a caller-supplied id is non-empty-checked by
// the caller and within the length bound.
func validPayloadID(id string) bool {
	return len(id) <= maxPayloadIDBytes
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
