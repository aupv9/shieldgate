//go:build integration

package gorm_test

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"shieldgate/internal/models"
	"shieldgate/internal/observability"
	gormrepo "shieldgate/internal/repo/gorm"
)

func TestIntegration_GormTracing_ChildSpansWithoutParameterValues(t *testing.T) {
	// Arrange
	exporter := tracetest.NewInMemoryExporter()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(provider)
	t.Cleanup(func() { otel.SetTracerProvider(prev) })

	db := openTestDB(t)
	require.NoError(t, db.Use(observability.GormTracing{}))
	sessions := gormrepo.NewSessionRepository(db)
	secretHash := "SECRET-HASH-" + uuid.NewString()
	ctx, parent := otel.Tracer("test").Start(context.Background(), "request")

	// Act
	_, err := sessions.GetByTokenHash(ctx, uuid.New(), secretHash)
	parent.End()

	// Assert
	assert.ErrorIs(t, err, models.ErrSessionNotFound)
	var dbSpan *tracetest.SpanStub
	for i, s := range exporter.GetSpans() {
		if s.Name == "db.query" {
			dbSpan = &exporter.GetSpans()[i]
		}
	}
	require.NotNil(t, dbSpan, "a span per database operation")
	assert.Equal(t, parent.SpanContext().SpanID(), dbSpan.Parent.SpanID(), "child of the request span")
	attrs := map[string]string{}
	for _, kv := range dbSpan.Attributes {
		attrs[string(kv.Key)] = kv.Value.Emit()
	}
	assert.Equal(t, "postgresql", attrs["db.system"])
	assert.Contains(t, attrs["db.query.text"], "token_hash = $2")
	for _, v := range attrs {
		assert.False(t, strings.Contains(v, secretHash), "parameter values never reach traces")
	}
	assert.NotEqual(t, "Error", dbSpan.Status.Code.String(), "not found is not a database error")
}
