package services

import (
	"context"
	"fmt"
	"time"

	"shieldgate/internal/models"
	"shieldgate/internal/repo"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type sessionServiceImpl struct {
	repos  *repo.Repositories
	logger *logrus.Logger
}

func NewSessionService(repos *repo.Repositories, logger *logrus.Logger) SessionService {
	return &sessionServiceImpl{repos: repos, logger: logger}
}

func (s *sessionServiceImpl) Create(ctx context.Context, tenantID, userID uuid.UUID, tokenID, ipAddress, userAgent, deviceName string, expiresAt time.Time) (*models.Session, error) {
	session := &models.Session{
		ID:           uuid.New(),
		TenantID:     tenantID,
		UserID:       userID,
		TokenID:      tokenID,
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
		DeviceName:   deviceName,
		LastActiveAt: time.Now(),
		ExpiresAt:    expiresAt,
	}
	if err := s.repos.Session.Create(ctx, session); err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}
	return session, nil
}

func (s *sessionServiceImpl) GetByID(ctx context.Context, tenantID, sessionID uuid.UUID) (*models.Session, error) {
	session, err := s.repos.Session.GetByID(ctx, tenantID, sessionID)
	if err != nil {
		return nil, models.ErrSessionNotFound
	}
	if session.IsRevoked() {
		return nil, models.ErrSessionRevoked
	}
	if session.IsExpired() {
		return nil, models.ErrSessionExpired
	}
	return session, nil
}

func (s *sessionServiceImpl) GetByTokenID(ctx context.Context, tokenID string) (*models.Session, error) {
	session, err := s.repos.Session.GetByTokenID(ctx, tokenID)
	if err != nil {
		return nil, models.ErrSessionNotFound
	}
	return session, nil
}

func (s *sessionServiceImpl) ListByUser(ctx context.Context, tenantID, userID uuid.UUID, limit, offset int) (*models.SessionListResponse, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	sessions, total, err := s.repos.Session.ListByUser(ctx, tenantID, userID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list sessions: %w", err)
	}
	return &models.SessionListResponse{Sessions: sessions, Total: total}, nil
}

func (s *sessionServiceImpl) Revoke(ctx context.Context, tenantID, sessionID uuid.UUID) error {
	if err := s.repos.Session.Revoke(ctx, tenantID, sessionID); err != nil {
		return fmt.Errorf("failed to revoke session: %w", err)
	}
	s.logger.WithFields(logrus.Fields{
		"tenant_id":  tenantID,
		"session_id": sessionID,
	}).Info("session revoked")
	return nil
}

func (s *sessionServiceImpl) RevokeAll(ctx context.Context, tenantID, userID uuid.UUID) error {
	if err := s.repos.Session.RevokeAll(ctx, tenantID, userID); err != nil {
		return fmt.Errorf("failed to revoke all sessions: %w", err)
	}
	s.logger.WithFields(logrus.Fields{
		"tenant_id": tenantID,
		"user_id":   userID,
	}).Info("all sessions revoked")
	return nil
}

func (s *sessionServiceImpl) UpdateLastActive(ctx context.Context, sessionID uuid.UUID) error {
	session, err := s.repos.Session.GetByTokenID(ctx, sessionID.String())
	if err != nil {
		return nil // best-effort, don't fail
	}
	session.LastActiveAt = time.Now()
	return s.repos.Session.Update(ctx, session)
}

func (s *sessionServiceImpl) CleanupExpired(ctx context.Context) error {
	return s.repos.Session.DeleteExpired(ctx)
}
