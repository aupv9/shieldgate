// Package observability provides Prometheus metrics, OpenTelemetry tracing
// and the recorder that turns security-relevant events into metrics and
// audit log entries.
package observability

import (
	"context"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/trace"
)

// RequestInfo describes the HTTP request behind an operation, so code that
// only sees a context.Context (services, the audit log) can attribute it
type RequestInfo struct {
	RequestID string
	IPAddress string
	UserAgent string
}

type requestInfoKey struct{}

// WithRequestInfo returns ctx carrying info
func WithRequestInfo(ctx context.Context, info RequestInfo) context.Context {
	return context.WithValue(ctx, requestInfoKey{}, info)
}

// RequestInfoFrom returns the request info in ctx, if any
func RequestInfoFrom(ctx context.Context) (RequestInfo, bool) {
	info, ok := ctx.Value(requestInfoKey{}).(RequestInfo)
	return info, ok
}

// TraceID returns the trace ID of the span in ctx, or "" if none is sampled
func TraceID(ctx context.Context) string {
	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() {
		return ""
	}
	return sc.TraceID().String()
}

// RequestContext copies the request ID, client IP and user agent into the
// request's context. requestIDKey is the gin key the request ID is stored
// under; it must run after the middleware that sets it.
func RequestContext(requestIDKey string) gin.HandlerFunc {
	return func(c *gin.Context) {
		info := RequestInfo{
			RequestID: c.GetString(requestIDKey),
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
		}
		c.Request = c.Request.WithContext(WithRequestInfo(c.Request.Context(), info))
		c.Next()
	}
}
