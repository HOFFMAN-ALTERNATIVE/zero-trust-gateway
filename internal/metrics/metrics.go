// Package metrics holds the gateway's Prometheus instruments on a private
// registry (no global state, safe for parallel tests).
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics groups all instruments.
type Metrics struct {
	Registry       *prometheus.Registry
	Requests       *prometheus.CounterVec
	Duration       *prometheus.HistogramVec
	AuthnFailures  *prometheus.CounterVec
	UpstreamErrors *prometheus.CounterVec
	JWKSRefresh    *prometheus.CounterVec
	JWKSKeys       prometheus.Gauge
	Sessions       prometheus.Counter
	Reloads        *prometheus.CounterVec
}

// New registers everything on a fresh registry.
func New() *Metrics {
	m := &Metrics{
		Registry: prometheus.NewRegistry(),
		Requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ztg_requests_total", Help: "Requests by route, policy decision and status code.",
		}, []string{"route", "decision", "code"}),
		Duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "ztg_request_duration_seconds", Help: "End-to-end request latency through the gateway.",
			Buckets: []float64{.001, .0025, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5},
		}, []string{"route"}),
		AuthnFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ztg_authn_failures_total", Help: "Rejected credentials by reason.",
		}, []string{"reason"}),
		UpstreamErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ztg_upstream_errors_total", Help: "Transport errors talking to upstreams (incl. mTLS failures).",
		}, []string{"upstream"}),
		JWKSRefresh: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ztg_jwks_refresh_total", Help: "JWKS fetches by result.",
		}, []string{"result"}),
		JWKSKeys: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ztg_jwks_keys", Help: "Signing keys currently cached.",
		}),
		Sessions: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "ztg_sessions_issued_total", Help: "Session cookies issued after OIDC login.",
		}),
		Reloads: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ztg_policy_reloads_total", Help: "Policy reloads (SIGHUP) by result.",
		}, []string{"result"}),
	}
	m.Registry.MustRegister(m.Requests, m.Duration, m.AuthnFailures, m.UpstreamErrors,
		m.JWKSRefresh, m.JWKSKeys, m.Sessions, m.Reloads,
		collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	return m
}

// Handler serves the registry.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{Registry: m.Registry})
}
