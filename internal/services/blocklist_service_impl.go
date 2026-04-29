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

type blocklistServiceImpl struct {
	repos  *repo.Repositories
	logger *logrus.Logger
}

// NewBlocklistService creates a new BlocklistService.
func NewBlocklistService(repos *repo.Repositories, logger *logrus.Logger) BlocklistService {
	return &blocklistServiceImpl{repos: repos, logger: logger}
}

func (s *blocklistServiceImpl) Block(ctx context.Context, jti string, tenantID, userID uuid.UUID, expiresAt time.Time) error {
	entry := &models.TokenBlocklist{
		JTI:       jti,
		TenantID:  tenantID,
		UserID:    userID,
		ExpiresAt: expiresAt,
	}
	if err := s.repos.Blocklist.Add(ctx, entry); err != nil {
		return fmt.Errorf("blocklist add: %w", err)
	}
	s.logger.WithFields(logrus.Fields{
		"jti":       jti,
		"tenant_id": tenantID,
		"user_id":   userID,
	}).Debug("token blocked")
	return nil
}

func (s *blocklistServiceImpl) IsBlocked(ctx context.Context, jti string) (bool, error) {
	blocked, err := s.repos.Blocklist.IsBlocked(ctx, jti)
	if err != nil {
		return false, fmt.Errorf("blocklist check: %w", err)
	}
	return blocked, nil
}

func (s *blocklistServiceImpl) Cleanup(ctx context.Context) error {
	if err := s.repos.Blocklist.DeleteExpired(ctx); err != nil {
		return fmt.Errorf("blocklist cleanup: %w", err)
	}
	return nil
}
