// Package metrics exposes Prometheus metrics for pdn-shield.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics holds all Prometheus collectors.
type Metrics struct {
	Registry        *prometheus.Registry
	RequestsTotal   *prometheus.CounterVec
	RequestDuration *prometheus.HistogramVec
	Inflight        prometheus.Gauge
	PIIFound        *prometheus.CounterVec
	Tokens          *prometheus.CounterVec
	LLMDuration     prometheus.Histogram
	Rejected        *prometheus.CounterVec
	StoreErrors     *prometheus.CounterVec
}

// New builds the metrics registry.
func New() *Metrics {
	reg := prometheus.NewRegistry()
	f := promauto.With(reg)
	return &Metrics{
		Registry: reg,
		RequestsTotal: f.NewCounterVec(prometheus.CounterOpts{
			Name: "pdn_requests_total",
			Help: "Total HTTP requests by route, system and status.",
		}, []string{"route", "system", "status"}),
		RequestDuration: f.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "pdn_request_duration_seconds",
			Help:    "Request duration in seconds by route.",
			Buckets: []float64{0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1, 2, 5},
		}, []string{"route"}),
		Inflight: f.NewGauge(prometheus.GaugeOpts{
			Name: "pdn_inflight",
			Help: "Number of requests currently being processed.",
		}),
		PIIFound: f.NewCounterVec(prometheus.CounterOpts{
			Name: "pdn_pii_found_total",
			Help: "Total PII spans found by category.",
		}, []string{"category"}),
		Tokens: f.NewCounterVec(prometheus.CounterOpts{
			Name: "pdn_tokens_total",
			Help: "Estimated tokens processed by direction.",
		}, []string{"direction"}),
		LLMDuration: f.NewHistogram(prometheus.HistogramOpts{
			Name:    "pdn_llm_duration_seconds",
			Help:    "Upstream LLM call duration in seconds.",
			Buckets: []float64{0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60},
		}),
		Rejected: f.NewCounterVec(prometheus.CounterOpts{
			Name: "pdn_rejected_total",
			Help: "Total rejected requests by reason.",
		}, []string{"reason"}),
		StoreErrors: f.NewCounterVec(prometheus.CounterOpts{
			Name: "pdn_store_errors_total",
			Help: "Total store errors by operation.",
		}, []string{"operation"}),
	}
}

// EstimateTokens estimates the token count of a text: runes/3 for Cyrillic
// dominated text, otherwise a rough runes/4 heuristic.
func EstimateTokens(text string) int {
	runes := 0
	for range text {
		runes++
	}
	if runes == 0 {
		return 0
	}
	return runes/3 + 1
}
