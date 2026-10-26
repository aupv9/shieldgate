package observability

import (
	"database/sql"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const namespace = "shieldgate"

// Label values come from bounded sets: anything a client can choose freely
// (paths, grant types, error codes) is normalized so a caller cannot create
// unbounded time series.
var (
	knownMethods = map[string]bool{
		http.MethodGet: true, http.MethodPost: true, http.MethodPut: true, http.MethodPatch: true,
		http.MethodDelete: true, http.MethodHead: true, http.MethodOptions: true,
	}
	knownGrantTypes = map[string]bool{
		"authorization_code": true, "refresh_token": true, "client_credentials": true,
		"urn:ietf:params:oauth:grant-type:device_code":    true,
		"urn:ietf:params:oauth:grant-type:token-exchange": true,
	}
	// OAuth error codes (RFC 6749 §5.2, RFC 8628 §3.5, RFC 8693 §2.2.2)
	knownTokenErrors = map[string]bool{
		"invalid_request": true, "invalid_client": true, "invalid_grant": true, "unauthorized_client": true,
		"unsupported_grant_type": true, "invalid_scope": true, "invalid_target": true, "server_error": true,
		"authorization_pending": true, "slow_down": true, "access_denied": true, "expired_token": true,
	}
)

// Metrics holds the server's Prometheus collectors on a private registry
type Metrics struct {
	registry *prometheus.Registry

	httpRequests    *prometheus.CounterVec
	httpDuration    *prometheus.HistogramVec
	httpInFlight    prometheus.Gauge
	tokenRequests   *prometheus.CounterVec
	tokensIssued    *prometheus.CounterVec
	tokensRevoked   prometheus.Counter
	tokenReuse      *prometheus.CounterVec
	authEvents      *prometheus.CounterVec
	auditFailures   prometheus.Counter
	emailsProcessed *prometheus.CounterVec
}

// NewMetrics creates the collectors, including Go runtime and process
// metrics, on a new registry
func NewMetrics() *Metrics {
	m := &Metrics{
		registry: prometheus.NewRegistry(),
		httpRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "http_requests_total",
			Help: "HTTP requests by method, route template and status code.",
		}, []string{"method", "route", "status"}),
		httpDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace, Name: "http_request_duration_seconds",
			Help:    "HTTP request latency by method and route template.",
			Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
		}, []string{"method", "route"}),
		httpInFlight: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Name: "http_requests_in_flight",
			Help: "HTTP requests currently being served.",
		}),
		tokenRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "token_requests_total",
			Help: "Token endpoint requests by grant type and result (success or OAuth error code).",
		}, []string{"grant_type", "result"}),
		tokensIssued: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "tokens_issued_total",
			Help: "Token sets issued by grant type.",
		}, []string{"grant_type"}),
		tokensRevoked: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace, Name: "tokens_revoked_total",
			Help: "Tokens revoked through the revocation endpoint.",
		}),
		tokenReuse: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "token_reuse_detected_total",
			Help: "Replays of single-use credentials; each revoked a token family.",
		}, []string{"credential"}),
		authEvents: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "auth_events_total",
			Help: "Interactive authentication events by event and result.",
		}, []string{"event", "result"}),
		auditFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace, Name: "audit_write_failures_total",
			Help: "Audit log entries that could not be written.",
		}),
		emailsProcessed: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "emails_processed_total",
			Help: "Queued emails processed by result (sent, retry, failed).",
		}, []string{"result"}),
	}
	m.registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		m.httpRequests, m.httpDuration, m.httpInFlight,
		m.tokenRequests, m.tokensIssued, m.tokensRevoked, m.tokenReuse,
		m.authEvents, m.auditFailures, m.emailsProcessed,
	)
	return m
}

// RegisterDB adds connection pool metrics for db
func (m *Metrics) RegisterDB(db *sql.DB) {
	m.registry.MustRegister(collectors.NewDBStatsCollector(db, namespace))
}

// Handler serves the metrics in the Prometheus exposition format
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{Registry: m.registry})
}

// Registry exposes the registry, for tests
func (m *Metrics) Registry() *prometheus.Registry {
	return m.registry
}

// HTTPMiddleware records request counts, latency and concurrency. Routes are
// labeled with their template (/v1/users/:user_id), never the raw path.
func (m *Metrics) HTTPMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if m == nil {
			c.Next()
			return
		}
		start := time.Now()
		m.httpInFlight.Inc()
		defer m.httpInFlight.Dec()

		c.Next()

		route := c.FullPath()
		if route == "" {
			route = "unmatched"
		}
		method := c.Request.Method
		if !knownMethods[method] {
			method = "OTHER"
		}
		m.httpRequests.WithLabelValues(method, route, strconv.Itoa(c.Writer.Status())).Inc()
		m.httpDuration.WithLabelValues(method, route).Observe(time.Since(start).Seconds())
	}
}

// TokenRequest counts a token endpoint request; result is "success" or the
// OAuth error code returned
func (m *Metrics) TokenRequest(grantType, result string) {
	if m == nil {
		return
	}
	if result != "success" && !knownTokenErrors[result] {
		result = "other"
	}
	m.tokenRequests.WithLabelValues(normalizeGrantType(grantType), result).Inc()
}

// EmailProcessed counts a queued email by outcome: sent, retry or failed
func (m *Metrics) EmailProcessed(result string) {
	if m == nil {
		return
	}
	m.emailsProcessed.WithLabelValues(result).Inc()
}

func normalizeGrantType(grantType string) string {
	switch {
	case grantType == "":
		return "none"
	case knownGrantTypes[grantType]:
		return grantType
	}
	return "other"
}
