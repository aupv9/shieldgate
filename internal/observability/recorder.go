package observability

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"shieldgate/internal/models"
)

// auditWriteTimeout bounds an audit write so a slow database delays a
// request by at most this much
const auditWriteTimeout = 3 * time.Second

// AuditLogger stores audit entries. services.AuditService satisfies it.
type AuditLogger interface {
	Log(ctx context.Context, entry *models.AuditLog) error
}

// Event is an interactive authentication event (login, MFA, consent,
// device approval, logout, account recovery) to audit and count
type Event struct {
	// Action is the audited action; empty records the metric only
	Action   models.AuditAction
	TenantID uuid.UUID
	UserID   *uuid.UUID
	ClientID *uuid.UUID
	// Resource defaults to "user"
	Resource  string
	Success   bool
	ErrorCode string
	Metadata  map[string]interface{}
	// Name and Result label the auth_events_total counter; both come from
	// fixed sets in the calling code. An empty Name skips the counter.
	Name   string
	Result string
}

// Recorder turns events into metrics and audit log entries. A nil Recorder,
// or one with nil parts, records nothing, so instrumentation is optional.
type Recorder struct {
	audit   AuditLogger
	metrics *Metrics
	logger  *logrus.Logger
}

// NewRecorder creates a Recorder; audit and metrics may be nil
func NewRecorder(audit AuditLogger, metrics *Metrics, logger *logrus.Logger) *Recorder {
	return &Recorder{audit: audit, metrics: metrics, logger: logger}
}

// Metrics returns the recorder's metrics, or nil
func (r *Recorder) Metrics() *Metrics {
	if r == nil {
		return nil
	}
	return r.metrics
}

// Record audits and counts an authentication event
func (r *Recorder) Record(ctx context.Context, ev Event) {
	if r == nil {
		return
	}
	if r.metrics != nil && ev.Name != "" {
		r.metrics.authEvents.WithLabelValues(ev.Name, ev.Result).Inc()
	}
	// Some events are only counted (an MFA prompt, a verified code that
	// is audited as the login it completes)
	if ev.Action == "" {
		return
	}
	resource := ev.Resource
	if resource == "" {
		resource = "user"
	}
	r.write(ctx, &models.AuditLog{
		TenantID:   ev.TenantID,
		UserID:     ev.UserID,
		ClientID:   ev.ClientID,
		Action:     ev.Action,
		Resource:   resource,
		ResourceID: ev.UserID,
		Success:    ev.Success,
		ErrorCode:  ev.ErrorCode,
		Metadata:   ev.Metadata,
	})
}

// TokenEvent audits and counts a token event; it implements
// services.TokenEventSink
func (r *Recorder) TokenEvent(ctx context.Context, ev models.TokenEvent) {
	if r == nil {
		return
	}
	metadata := map[string]interface{}{}
	entry := &models.AuditLog{
		TenantID: ev.TenantID,
		UserID:   ev.UserID,
		ClientID: &ev.ClientID,
		Resource: "token",
		Success:  true,
		Metadata: metadata,
	}
	if ev.FamilyID != uuid.Nil {
		entry.ResourceID = &ev.FamilyID
	}

	switch ev.Type {
	case models.TokenEventIssued:
		entry.Action = models.AuditActionTokenGenerated
		metadata["grant_type"] = ev.GrantType
		metadata["scope"] = ev.Scope
		if ev.Actor != "" {
			metadata["actor"] = ev.Actor
		}
		if r.metrics != nil {
			r.metrics.tokensIssued.WithLabelValues(normalizeGrantType(ev.GrantType)).Inc()
		}
	case models.TokenEventRevoked:
		entry.Action = models.AuditActionTokenRevoked
		if r.metrics != nil {
			r.metrics.tokensRevoked.Inc()
		}
	case models.TokenEventReuseDetected:
		// A replayed single-use credential: the family was revoked because
		// the credential may be in an attacker's hands
		entry.Action = models.AuditActionTokenReuseDetected
		entry.Success = false
		entry.ErrorCode = "token_reuse"
		metadata["credential"] = ev.Credential
		if r.metrics != nil {
			r.metrics.tokenReuse.WithLabelValues(ev.Credential).Inc()
		}
	default:
		return
	}
	r.write(ctx, entry)
}

// write stores an audit entry with the request's attribution. Failures are
// logged and counted, never returned: the audited operation already happened.
func (r *Recorder) write(ctx context.Context, entry *models.AuditLog) {
	if r.audit == nil {
		return
	}
	if info, ok := RequestInfoFrom(ctx); ok {
		entry.RequestID = info.RequestID
		entry.IPAddress = info.IPAddress
		entry.UserAgent = info.UserAgent
	}
	if traceID := TraceID(ctx); traceID != "" {
		if entry.Metadata == nil {
			entry.Metadata = map[string]interface{}{}
		}
		entry.Metadata["trace_id"] = traceID
	}

	// The request may already be finished or cancelled; the entry must still
	// be written
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditWriteTimeout)
	defer cancel()
	if err := r.audit.Log(writeCtx, entry); err != nil {
		if r.metrics != nil {
			r.metrics.auditFailures.Inc()
		}
		if r.logger != nil {
			r.logger.WithError(err).WithFields(logrus.Fields{
				"action":     entry.Action,
				"tenant_id":  entry.TenantID,
				"request_id": entry.RequestID,
			}).Error("failed to write audit log")
		}
	}
}
