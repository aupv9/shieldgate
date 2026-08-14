package services

// session_consent_service.go implements server-side SSO sessions and
// remembered consent grants on authServiceImpl.

import (
	"context"
	"strings"
	"time"

	"shieldgate/internal/models"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// CreateSession starts a browser session after a successful login and returns
// the raw cookie value (only its hash is stored).
func (s *authServiceImpl) CreateSession(ctx context.Context, tenantID, userID uuid.UUID, ipAddress, userAgent string) (string, *models.UserSession, error) {
	token, err := s.generateRandomString(48)
	if err != nil {
		return "", nil, err
	}

	duration := s.config.SessionDuration
	if duration <= 0 {
		duration = 24 * time.Hour
	}

	now := time.Now()
	session := &models.UserSession{
		ID:        uuid.New(),
		TenantID:  tenantID,
		UserID:    userID,
		Token:     hashToken(token),
		IPAddress: ipAddress,
		UserAgent: userAgent,
		AuthTime:  now,
		ExpiresAt: now.Add(duration),
	}
	if err := s.repos.Session.Create(ctx, session); err != nil {
		return "", nil, err
	}

	s.logger.WithFields(logrus.Fields{
		"tenant_id": tenantID,
		"user_id":   userID,
	}).Info("user session created")

	return token, session, nil
}

// GetSession resolves a session cookie value to a live session
func (s *authServiceImpl) GetSession(ctx context.Context, tenantID uuid.UUID, token string) (*models.UserSession, error) {
	if token == "" {
		return nil, models.ErrSessionNotFound
	}
	session, err := s.repos.Session.GetByToken(ctx, tenantID, hashToken(token))
	if err != nil {
		return nil, models.ErrSessionNotFound
	}
	if session.IsRevoked() {
		return nil, models.ErrSessionNotFound
	}
	if session.IsExpired() {
		return nil, models.ErrSessionExpired
	}
	return session, nil
}

// RevokeSession ends a session (logout)
func (s *authServiceImpl) RevokeSession(ctx context.Context, tenantID uuid.UUID, token string) error {
	if token == "" {
		return nil
	}
	return s.repos.Session.Revoke(ctx, tenantID, hashToken(token))
}

// HasConsent reports whether the user has already granted the client every
// scope in the requested set (union of unrevoked grants)
func (s *authServiceImpl) HasConsent(ctx context.Context, tenantID, userID, clientID uuid.UUID, scope string) (bool, error) {
	consents, err := s.repos.Consent.ListByUserAndClient(ctx, tenantID, userID, clientID)
	if err != nil {
		return false, err
	}

	granted := make([]string, 0, len(consents))
	for _, consent := range consents {
		granted = append(granted, consent.Scope)
	}
	return ScopeIsSubset(scope, strings.Join(granted, " ")), nil
}

// GrantConsent remembers that the user approved the client for the scope set
func (s *authServiceImpl) GrantConsent(ctx context.Context, tenantID, userID, clientID uuid.UUID, scope string) error {
	consent := &models.UserConsent{
		ID:       uuid.New(),
		TenantID: tenantID,
		UserID:   userID,
		ClientID: clientID,
		Scope:    scope,
	}
	if err := s.repos.Consent.Create(ctx, consent); err != nil {
		return err
	}

	s.logger.WithFields(logrus.Fields{
		"tenant_id": tenantID,
		"user_id":   userID,
		"client_id": clientID,
		"scope":     scope,
	}).Info("consent granted")
	return nil
}
