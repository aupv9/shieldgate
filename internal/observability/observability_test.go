package observability

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"shieldgate/internal/models"
)

type fakeAuditLog struct {
	mu      sync.Mutex
	entries []*models.AuditLog
	err     error
}

func (f *fakeAuditLog) Log(ctx context.Context, entry *models.AuditLog) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.entries = append(f.entries, entry)
	return nil
}

func quietLogger() *logrus.Logger {
	l := logrus.New()
	l.SetLevel(logrus.FatalLevel)
	return l
}

func TestHTTPMiddleware_LabelsByRouteTemplateNotRawPath(t *testing.T) {
	// Arrange
	gin.SetMode(gin.TestMode)
	m := NewMetrics()
	r := gin.New()
	r.Use(m.HTTPMiddleware())
	r.GET("/v1/users/:user_id", func(c *gin.Context) { c.Status(http.StatusOK) })

	// Act
	for _, path := range []string{"/v1/users/" + uuid.NewString(), "/v1/users/" + uuid.NewString(), "/nope/" + uuid.NewString()} {
		r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, path, nil))
	}
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("BREW", "/v1/users/x", nil))

	// Assert
	assert.Equal(t, 2.0, testutil.ToFloat64(m.httpRequests.WithLabelValues("GET", "/v1/users/:user_id", "200")))
	assert.Equal(t, 1.0, testutil.ToFloat64(m.httpRequests.WithLabelValues("GET", "unmatched", "404")))
	assert.Equal(t, 1.0, testutil.ToFloat64(m.httpRequests.WithLabelValues("OTHER", "unmatched", "404")))
	assert.Equal(t, 3, testutil.CollectAndCount(m.httpRequests), "one series per route template, not per path")
	assert.Zero(t, testutil.ToFloat64(m.httpInFlight))
}

func TestTokenRequest_NormalizesClientControlledLabels(t *testing.T) {
	// Arrange
	m := NewMetrics()

	// Act
	m.TokenRequest("authorization_code", "success")
	m.TokenRequest("authorization_code", "invalid_grant")
	m.TokenRequest("password-"+uuid.NewString(), "invalid_grant")
	m.TokenRequest("refresh_token", "made-up-"+uuid.NewString())
	m.TokenRequest("", "unsupported_grant_type")

	// Assert
	assert.Equal(t, 1.0, testutil.ToFloat64(m.tokenRequests.WithLabelValues("authorization_code", "success")))
	assert.Equal(t, 1.0, testutil.ToFloat64(m.tokenRequests.WithLabelValues("other", "invalid_grant")))
	assert.Equal(t, 1.0, testutil.ToFloat64(m.tokenRequests.WithLabelValues("refresh_token", "other")))
	assert.Equal(t, 1.0, testutil.ToFloat64(m.tokenRequests.WithLabelValues("none", "unsupported_grant_type")))
}

func TestMetricsHandler_ExposesShieldGateAndRuntimeMetrics(t *testing.T) {
	// Arrange
	m := NewMetrics()
	m.TokenRequest("client_credentials", "success")
	w := httptest.NewRecorder()

	// Act
	m.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	// Assert
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `shieldgate_token_requests_total{grant_type="client_credentials",result="success"} 1`)
	assert.Contains(t, w.Body.String(), "go_goroutines")
}

func TestRecorder_TokenEvents_AuditAndCount(t *testing.T) {
	// Arrange
	audit := &fakeAuditLog{}
	m := NewMetrics()
	r := NewRecorder(audit, m, quietLogger())
	tenantID, clientID, userID, familyID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	ctx := WithRequestInfo(context.Background(), RequestInfo{RequestID: "req-1", IPAddress: "203.0.113.7", UserAgent: "curl"})

	// Act
	r.TokenEvent(ctx, models.TokenEvent{Type: models.TokenEventIssued, TenantID: tenantID, ClientID: clientID, UserID: &userID,
		GrantType: models.GrantTypeRefreshToken, Scope: "openid", FamilyID: familyID})
	r.TokenEvent(ctx, models.TokenEvent{Type: models.TokenEventReuseDetected, TenantID: tenantID, ClientID: clientID, UserID: &userID,
		FamilyID: familyID, Credential: models.CredentialRefreshToken})
	r.TokenEvent(ctx, models.TokenEvent{Type: models.TokenEventRevoked, TenantID: tenantID, ClientID: clientID, FamilyID: familyID})

	// Assert
	require.Len(t, audit.entries, 3)
	issued, reuse, revoked := audit.entries[0], audit.entries[1], audit.entries[2]
	assert.Equal(t, models.AuditActionTokenGenerated, issued.Action)
	assert.True(t, issued.Success)
	assert.Equal(t, "refresh_token", issued.Metadata["grant_type"])
	assert.Equal(t, &familyID, issued.ResourceID)
	assert.Equal(t, "req-1", issued.RequestID)
	assert.Equal(t, "203.0.113.7", issued.IPAddress)
	assert.Equal(t, models.AuditActionTokenReuseDetected, reuse.Action)
	assert.False(t, reuse.Success, "a replay is a security failure")
	assert.Equal(t, models.AuditActionTokenRevoked, revoked.Action)
	assert.Equal(t, 1.0, testutil.ToFloat64(m.tokensIssued.WithLabelValues("refresh_token")))
	assert.Equal(t, 1.0, testutil.ToFloat64(m.tokenReuse.WithLabelValues("refresh_token")))
	assert.Equal(t, 1.0, testutil.ToFloat64(m.tokensRevoked))
}

func TestRecorder_AuditFailure_CountedNotPropagated(t *testing.T) {
	// Arrange
	m := NewMetrics()
	r := NewRecorder(&fakeAuditLog{err: errors.New("db down")}, m, quietLogger())

	// Act
	r.Record(context.Background(), Event{Action: models.AuditActionUserLogin, TenantID: uuid.New(), Name: "login", Result: "success"})

	// Assert
	assert.Equal(t, 1.0, testutil.ToFloat64(m.auditFailures))
	assert.Equal(t, 1.0, testutil.ToFloat64(m.authEvents.WithLabelValues("login", "success")))
}

func TestRecorder_CancelledRequest_StillAudited(t *testing.T) {
	// Arrange
	audit := &fakeAuditLog{}
	r := NewRecorder(audit, nil, quietLogger())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Act
	r.Record(ctx, Event{Action: models.AuditActionUserLogout, TenantID: uuid.New()})

	// Assert
	require.Len(t, audit.entries, 1)
	assert.Equal(t, "user", audit.entries[0].Resource)
}

func TestRecorder_NilIsSafe(t *testing.T) {
	var r *Recorder
	assert.NotPanics(t, func() {
		r.Record(context.Background(), Event{Name: "login", Result: "success"})
		r.TokenEvent(context.Background(), models.TokenEvent{Type: models.TokenEventIssued})
		r.Metrics().TokenRequest("authorization_code", "success")
		r.Metrics().EmailProcessed("sent")
	})
}

// installTestTracer routes spans to an in-memory exporter for one test
func installTestTracer(t *testing.T) *tracetest.InMemoryExporter {
	t.Helper()
	exporter := tracetest.NewInMemoryExporter()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	prevProvider, prevPropagator := otel.GetTracerProvider(), otel.GetTextMapPropagator()
	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	t.Cleanup(func() {
		otel.SetTracerProvider(prevProvider)
		otel.SetTextMapPropagator(prevPropagator)
	})
	return exporter
}

func TestTracingMiddleware_SpanPerRouteWithoutSecrets(t *testing.T) {
	// Arrange
	exporter := installTestTracer(t)
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(TracingMiddleware("tenant_id"))
	var handlerTraceID string
	r.POST("/oauth/token", func(c *gin.Context) {
		c.Set("tenant_id", "t-1")
		handlerTraceID = TraceID(c.Request.Context())
		c.Status(http.StatusInternalServerError)
	})
	req := httptest.NewRequest(http.MethodPost, "/oauth/token?code=SECRET-CODE", strings.NewReader("password=hunter2"))
	req.Header.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")

	// Act
	r.ServeHTTP(httptest.NewRecorder(), req)

	// Assert
	spans := exporter.GetSpans()
	require.Len(t, spans, 1)
	span := spans[0]
	assert.Equal(t, "POST /oauth/token", span.Name)
	assert.Equal(t, "4bf92f3577b34da6a3ce929d0e0e4736", span.SpanContext.TraceID().String(), "continues the caller's trace")
	assert.Equal(t, "4bf92f3577b34da6a3ce929d0e0e4736", handlerTraceID, "handlers see the span in their context")
	assert.Equal(t, codes.Error, span.Status.Code)
	for _, kv := range span.Attributes {
		assert.NotContains(t, kv.Value.Emit(), "SECRET-CODE")
		assert.NotContains(t, kv.Value.Emit(), "hunter2")
	}
	attrs := map[string]string{}
	for _, kv := range span.Attributes {
		attrs[string(kv.Key)] = kv.Value.Emit()
	}
	assert.Equal(t, "/oauth/token", attrs["http.route"])
	assert.Equal(t, "500", attrs["http.response.status_code"])
	assert.Equal(t, "t-1", attrs["shieldgate.tenant_id"])
}

func TestRecorder_AddsTraceIDToAudit(t *testing.T) {
	// Arrange
	installTestTracer(t)
	audit := &fakeAuditLog{}
	r := NewRecorder(audit, nil, quietLogger())
	ctx, span := otel.Tracer("test").Start(context.Background(), "op")
	defer span.End()

	// Act
	r.Record(ctx, Event{Action: models.AuditActionUserLogin, TenantID: uuid.New()})

	// Assert
	require.Len(t, audit.entries, 1)
	assert.Equal(t, span.SpanContext().TraceID().String(), audit.entries[0].Metadata["trace_id"])
}

func TestSetupTracing_WithoutEndpoint_IsNoop(t *testing.T) {
	// Arrange
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")
	before := otel.GetTracerProvider()

	// Act
	shutdown, err := SetupTracing(context.Background(), "test")

	// Assert
	require.NoError(t, err)
	assert.False(t, TracingEnabled())
	assert.Equal(t, before, otel.GetTracerProvider(), "no provider is installed")
	assert.NoError(t, shutdown(context.Background()))
}

func TestRequestContext_CopiesRequestInfo(t *testing.T) {
	// Arrange
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("request_id", "req-9"); c.Next() })
	r.Use(RequestContext("request_id"))
	var got RequestInfo
	r.GET("/x", func(c *gin.Context) { got, _ = RequestInfoFrom(c.Request.Context()) })
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("User-Agent", "probe/1")

	// Act
	r.ServeHTTP(httptest.NewRecorder(), req)

	// Assert
	assert.Equal(t, "req-9", got.RequestID)
	assert.Equal(t, "probe/1", got.UserAgent)
	assert.NotEmpty(t, got.IPAddress)
}

func TestRecorder_MetricOnlyEvent_NotAudited(t *testing.T) {
	// Arrange
	audit := &fakeAuditLog{}
	m := NewMetrics()
	r := NewRecorder(audit, m, quietLogger())

	// Act
	r.Record(context.Background(), Event{Name: "login", Result: "mfa_required"})

	// Assert
	assert.Empty(t, audit.entries, "an event without an action must not produce an empty audit entry")
	assert.Equal(t, 1.0, testutil.ToFloat64(m.authEvents.WithLabelValues("login", "mfa_required")))
}
