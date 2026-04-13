package middleware

import (
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
)

// requestLabel is the composite key for per-route request counters.
type requestLabel struct {
	method string
	path   string
	status int
}

// durationLabel is the composite key for per-route latency histograms.
type durationLabel struct {
	method string
	path   string
}

// metricsRegistry holds all in-memory counters and latency samples.
// It is package-level so MetricsMiddleware and MetricsHandler share state.
type metricsRegistry struct {
	mu              sync.RWMutex
	requestsTotal   map[requestLabel]int64
	requestDuration map[durationLabel][]float64
	tokensIssued    atomic.Int64
	authFailures    atomic.Int64
}

var registry = &metricsRegistry{
	requestsTotal:   make(map[requestLabel]int64),
	requestDuration: make(map[durationLabel][]float64),
}

// IncrementTokensIssued records a successful OAuth token issuance.
// Call this from the token endpoint handler after generating tokens.
func IncrementTokensIssued() { registry.tokensIssued.Add(1) }

// IncrementAuthFailures records an authentication failure.
// Call this from handlers that reject invalid credentials.
func IncrementAuthFailures() { registry.authFailures.Add(1) }

// MetricsMiddleware records per-route HTTP request counts and mean latency.
// Add this to the router before registering routes.
func MetricsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		elapsed := time.Since(start).Seconds()

		rl := requestLabel{method: c.Request.Method, path: c.FullPath(), status: c.Writer.Status()}
		dl := durationLabel{method: c.Request.Method, path: c.FullPath()}

		registry.mu.Lock()
		registry.requestsTotal[rl]++
		registry.requestDuration[dl] = append(registry.requestDuration[dl], elapsed)
		registry.mu.Unlock()
	}
}

// MetricsHandler returns a Gin handler that exposes metrics in Prometheus
// text format (text/plain; version=0.0.4). Register it at GET /metrics.
func MetricsHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		registry.mu.RLock()
		defer registry.mu.RUnlock()

		c.Status(http.StatusOK)
		c.Header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w := c.Writer

		// http_requests_total
		fmt.Fprintln(w, "# HELP http_requests_total Total HTTP requests processed.")
		fmt.Fprintln(w, "# TYPE http_requests_total counter")
		for lbl, count := range registry.requestsTotal {
			fmt.Fprintf(w, `http_requests_total{method=%q,path=%q,status=%q} %d`+"\n",
				lbl.method, lbl.path, strconv.Itoa(lbl.status), count)
		}

		// http_request_duration_seconds_mean (mean per route)
		fmt.Fprintln(w, "# HELP http_request_duration_seconds_mean Mean HTTP request latency in seconds.")
		fmt.Fprintln(w, "# TYPE http_request_duration_seconds_mean gauge")
		for lbl, samples := range registry.requestDuration {
			if len(samples) == 0 {
				continue
			}
			var sum float64
			for _, d := range samples {
				sum += d
			}
			avg := sum / float64(len(samples))
			fmt.Fprintf(w, `http_request_duration_seconds_mean{method=%q,path=%q} %s`+"\n",
				lbl.method, lbl.path, strconv.FormatFloat(avg, 'f', 6, 64))
		}

		// oauth_tokens_issued_total
		fmt.Fprintln(w, "# HELP oauth_tokens_issued_total Total OAuth tokens successfully issued.")
		fmt.Fprintln(w, "# TYPE oauth_tokens_issued_total counter")
		fmt.Fprintf(w, "oauth_tokens_issued_total %d\n", registry.tokensIssued.Load())

		// oauth_auth_failures_total
		fmt.Fprintln(w, "# HELP oauth_auth_failures_total Total authentication failures.")
		fmt.Fprintln(w, "# TYPE oauth_auth_failures_total counter")
		fmt.Fprintf(w, "oauth_auth_failures_total %d\n", registry.authFailures.Load())
	}
}
