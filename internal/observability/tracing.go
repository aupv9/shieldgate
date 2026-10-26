package observability

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

// TracerName identifies spans created by ShieldGate itself
const TracerName = "shieldgate"

// TracingEnabled reports whether an OTLP endpoint is configured through the
// standard OTEL_EXPORTER_OTLP_* environment variables
func TracingEnabled() bool {
	return os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") != "" || os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") != ""
}

// SetupTracing installs a global tracer provider exporting over OTLP/HTTP
// and the W3C trace context propagator. Exporter, sampler and resource are
// configured with the standard OTEL_* environment variables
// (OTEL_EXPORTER_OTLP_ENDPOINT, OTEL_TRACES_SAMPLER, OTEL_SERVICE_NAME...).
// Without an endpoint it installs nothing and tracing costs nothing. The
// returned function flushes and stops the exporter.
func SetupTracing(ctx context.Context, serviceVersion string) (func(context.Context) error, error) {
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	if !TracingEnabled() {
		return func(context.Context) error { return nil }, nil
	}

	exporter, err := otlptracehttp.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create OTLP trace exporter: %w", err)
	}
	attrs := []attribute.KeyValue{semconv.ServiceVersion(serviceVersion)}
	if os.Getenv("OTEL_SERVICE_NAME") == "" {
		attrs = append(attrs, semconv.ServiceName("shieldgate"))
	}
	res, err := resource.Merge(resource.Default(), resource.NewSchemaless(attrs...))
	if err != nil {
		return nil, fmt.Errorf("failed to build trace resource: %w", err)
	}
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(provider)
	return provider.Shutdown, nil
}

// TracingMiddleware starts a server span per request, continuing a trace
// propagated by the caller. The span is named after the route template and
// deliberately records neither the query string nor the body: on an
// authorization server they carry codes, tokens and passwords.
func TracingMiddleware(tenantIDKey string) gin.HandlerFunc {
	tracer := otel.Tracer(TracerName)
	return func(c *gin.Context) {
		ctx := otel.GetTextMapPropagator().Extract(c.Request.Context(), propagation.HeaderCarrier(c.Request.Header))
		route := c.FullPath()
		if route == "" {
			route = "unmatched"
		}
		ctx, span := tracer.Start(ctx, c.Request.Method+" "+route,
			trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(
				semconv.HTTPRequestMethodKey.String(c.Request.Method),
				semconv.HTTPRoute(route),
				semconv.URLScheme(scheme(c.Request)),
			),
		)
		defer span.End()
		c.Request = c.Request.WithContext(ctx)

		c.Next()

		status := c.Writer.Status()
		span.SetAttributes(semconv.HTTPResponseStatusCode(status))
		if tenantID, ok := c.Get(tenantIDKey); ok {
			span.SetAttributes(attribute.String("shieldgate.tenant_id", fmt.Sprint(tenantID)))
		}
		if status >= http.StatusInternalServerError {
			span.SetStatus(codes.Error, strconv.Itoa(status))
		}
	}
}

func scheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}
