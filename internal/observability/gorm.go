package observability

import (
	"errors"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	"gorm.io/gorm"
)

const gormSpanKey = "shieldgate:span"

// GormTracing is a GORM plugin creating a client span per database
// operation, as a child of the span in the statement's context (repositories
// pass the request context via WithContext). The statement is recorded with
// placeholders; parameter values (token hashes, emails, secrets) never are.
type GormTracing struct{}

// Name implements gorm.Plugin
func (GormTracing) Name() string { return "shieldgate:tracing" }

// Initialize implements gorm.Plugin
func (GormTracing) Initialize(db *gorm.DB) error {
	tracer := otel.Tracer(TracerName)
	before := func(operation string) func(*gorm.DB) {
		return func(tx *gorm.DB) {
			ctx, span := tracer.Start(tx.Statement.Context, "db."+operation,
				trace.WithSpanKind(trace.SpanKindClient),
				trace.WithAttributes(semconv.DBSystemPostgreSQL, semconv.DBOperationName(operation)),
			)
			tx.Statement.Context = ctx
			tx.InstanceSet(gormSpanKey, span)
		}
	}
	after := func(tx *gorm.DB) {
		value, ok := tx.InstanceGet(gormSpanKey)
		if !ok {
			return
		}
		span, ok := value.(trace.Span)
		if !ok {
			return
		}
		defer span.End()
		if table := tx.Statement.Table; table != "" {
			span.SetAttributes(semconv.DBCollectionName(table))
		}
		span.SetAttributes(
			semconv.DBQueryText(tx.Statement.SQL.String()),
			attribute.Int64("db.rows_affected", tx.Statement.RowsAffected),
		)
		if err := tx.Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			span.RecordError(err)
			span.SetStatus(codes.Error, "database error")
		}
	}

	cb := db.Callback()
	hooks := []struct {
		operation string
		before    func(string, func(*gorm.DB)) error
		after     func(string, func(*gorm.DB)) error
	}{
		{"create", cb.Create().Before("gorm:create").Register, cb.Create().After("gorm:create").Register},
		{"query", cb.Query().Before("gorm:query").Register, cb.Query().After("gorm:query").Register},
		{"update", cb.Update().Before("gorm:update").Register, cb.Update().After("gorm:update").Register},
		{"delete", cb.Delete().Before("gorm:delete").Register, cb.Delete().After("gorm:delete").Register},
		{"row", cb.Row().Before("gorm:row").Register, cb.Row().After("gorm:row").Register},
		{"raw", cb.Raw().Before("gorm:raw").Register, cb.Raw().After("gorm:raw").Register},
	}
	for _, h := range hooks {
		if err := h.before("shieldgate:trace_before_"+h.operation, before(h.operation)); err != nil {
			return err
		}
		if err := h.after("shieldgate:trace_after_"+h.operation, after); err != nil {
			return err
		}
	}
	return nil
}
