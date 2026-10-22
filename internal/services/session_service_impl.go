package services

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"shieldgate/internal/models"
	"shieldgate/internal/repo"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// sessionTokenBytes is the entropy of a session cookie token (256 bits)
const sessionTokenBytes = 32

type sessionServiceImpl struct {
	sessions repo.SessionRepository
	consents repo.ConsentRepository
	duration time.Duration
	logger   *logrus.Logger
}

// NewSessionService creates a session service. duration is the absolute
// session lifetime; after it the user must authenticate again.
func NewSessionService(sessions repo.SessionRepository, consents repo.ConsentRepository, duration time.Duration, logger *logrus.Logger) SessionService {
	return &sessionServiceImpl{
		sessions: sessions,
		consents: consents,
		duration: duration,
		logger:   logger,
	}
}

func (s *sessionServiceImpl) CreateSession(ctx context.Context, tenantID, userID uuid.UUID, ipAddress, userAgent string) (string, *models.Session, error) {
	token, err := randomToken(sessionTokenBytes)
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate session token: %w", err)
	}

	now := time.Now()
	session := &models.Session{
		ID:        uuid.New(),
		TenantID:  tenantID,
		UserID:    userID,
		TokenHash: hashToken(token),
		AuthTime:  now,
		IPAddress: ipAddress,
		UserAgent: userAgent,
		ExpiresAt: now.Add(s.duration),
	}
	if err := s.sessions.Create(ctx, session); err != nil {
		return "", nil, fmt.Errorf("failed to store session: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"tenant_id":  tenantID,
		"user_id":    userID,
		"session_id": session.ID,
	}).Info("session created")

	return token, session, nil
}

func (s *sessionServiceImpl) GetSession(ctx context.Context, tenantID uuid.UUID, token string) (*models.Session, error) {
	if token == "" {
		return nil, models.ErrSessionNotFound
	}

	session, err := s.sessions.GetByTokenHash(ctx, tenantID, hashToken(token))
	if err != nil {
		return nil, err
	}
	if session.IsExpired() {
		if err := s.sessions.DeleteByTokenHash(ctx, tenantID, session.TokenHash); err != nil {
			s.logger.WithError(err).Warn("failed to delete expired session")
		}
		return nil, models.ErrSessionNotFound
	}
	return session, nil
}

func (s *sessionServiceImpl) EndSession(ctx context.Context, tenantID uuid.UUID, token string) error {
	if token == "" {
		return nil
	}
	return s.sessions.DeleteByTokenHash(ctx, tenantID, hashToken(token))
}

func (s *sessionServiceImpl) CleanupExpiredSessions(ctx context.Context) error {
	return s.sessions.DeleteExpired(ctx)
}

func (s *sessionServiceImpl) HasConsent(ctx context.Context, tenantID, userID, clientID uuid.UUID, scope string) (bool, error) {
	consent, err := s.consents.Get(ctx, tenantID, userID, clientID)
	if errors.Is(err, models.ErrResourceNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return ScopeIsSubset(scope, consent.Scope), nil
}

func (s *sessionServiceImpl) GrantConsent(ctx context.Context, tenantID, userID, clientID uuid.UUID, scope string) error {
	granted := ParseScope(scope)

	existing, err := s.consents.Get(ctx, tenantID, userID, clientID)
	switch {
	case err == nil:
		granted = unionScopes(ParseScope(existing.Scope), granted)
	case !errors.Is(err, models.ErrResourceNotFound):
		return err
	}

	return s.consents.Upsert(ctx, &models.Consent{
		ID:        uuid.New(),
		TenantID:  tenantID,
		UserID:    userID,
		ClientID:  clientID,
		Scope:     strings.Join(granted, " "),
		UpdatedAt: time.Now(),
	})
}

// unionScopes returns a followed by every entry of b not already in a
func unionScopes(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, list := range [][]string{a, b} {
		for _, s := range list {
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out
}
