package middleware

// metrics.go provides a dependency-free Prometheus-text-format /metrics
// endpoint: request counters by method/route/status, request duration sums,
// in-flight gauge, and process uptime.

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
)

type metricsRegistry struct {
	mu             sync.Mutex
	requestCounts  map[string]int64   // key: method|route|status
	durationSums   map[string]float64 // key: method|route (seconds)
	durationCounts map[string]int64
	inFlight       int64
	startedAt      time.Time
}

var registry = &metricsRegistry{
	requestCounts:  make(map[string]int64),
	durationSums:   make(map[string]float64),
	durationCounts: make(map[string]int64),
	startedAt:      time.Now(),
}

// Metrics records per-request counters. Register it before the routes.
func Metrics() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.URL.Path == "/metrics" {
			c.Next()
			return
		}

		atomic.AddInt64(&registry.inFlight, 1)
		start := time.Now()
		c.Next()
		atomic.AddInt64(&registry.inFlight, -1)

		route := c.FullPath() // templated route, avoids high-cardinality raw paths
		if route == "" {
			route = "unmatched"
		}
		elapsed := time.Since(start).Seconds()
		countKey := c.Request.Method + "|" + route + "|" + strconv.Itoa(c.Writer.Status())
		durationKey := c.Request.Method + "|" + route

		registry.mu.Lock()
		registry.requestCounts[countKey]++
		registry.durationSums[durationKey] += elapsed
		registry.durationCounts[durationKey]++
		registry.mu.Unlock()
	}
}

// MetricsHandler serves GET /metrics in Prometheus text exposition format
func MetricsHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		var b strings.Builder

		registry.mu.Lock()
		b.WriteString("# HELP http_requests_total Total HTTP requests by method, route and status.\n")
		b.WriteString("# TYPE http_requests_total counter\n")
		for _, key := range sortedKeys(registry.requestCounts) {
			parts := strings.SplitN(key, "|", 3)
			fmt.Fprintf(&b, "http_requests_total{method=%q,path=%q,status=%q} %d\n",
				parts[0], parts[1], parts[2], registry.requestCounts[key])
		}

		b.WriteString("# HELP http_request_duration_seconds_sum Cumulative request duration by method and route.\n")
		b.WriteString("# TYPE http_request_duration_seconds summary\n")
		durationKeys := make([]string, 0, len(registry.durationSums))
		for key := range registry.durationSums {
			durationKeys = append(durationKeys, key)
		}
		sort.Strings(durationKeys)
		for _, key := range durationKeys {
			parts := strings.SplitN(key, "|", 2)
			fmt.Fprintf(&b, "http_request_duration_seconds_sum{method=%q,path=%q} %f\n",
				parts[0], parts[1], registry.durationSums[key])
			fmt.Fprintf(&b, "http_request_duration_seconds_count{method=%q,path=%q} %d\n",
				parts[0], parts[1], registry.durationCounts[key])
		}
		registry.mu.Unlock()

		b.WriteString("# HELP http_requests_in_flight Current number of in-flight HTTP requests.\n")
		b.WriteString("# TYPE http_requests_in_flight gauge\n")
		fmt.Fprintf(&b, "http_requests_in_flight %d\n", atomic.LoadInt64(&registry.inFlight))

		b.WriteString("# HELP process_uptime_seconds Seconds since the server started.\n")
		b.WriteString("# TYPE process_uptime_seconds gauge\n")
		fmt.Fprintf(&b, "process_uptime_seconds %f\n", time.Since(registry.startedAt).Seconds())

		c.Data(http.StatusOK, "text/plain; version=0.0.4; charset=utf-8", []byte(b.String()))
	}
}

func sortedKeys(m map[string]int64) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
