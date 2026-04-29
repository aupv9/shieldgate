package services

import (
	"context"
	"errors"
	"fmt"
	"time"

	"shieldgate/internal/models"
	"shieldgate/internal/repo"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type consentServiceImpl struct {
	repos  *repo.Repositories
	logger *logrus.Logger
}

// NewConsentService creates a new ConsentService.
func NewConsentService(repos *repo.Repositories, logger *logrus.Logger) ConsentService {
	return &consentServiceImpl{repos: repos, logger: logger}
}

func (s *consentServiceImpl) HasConsent(ctx context.Context, tenantID, userID, clientID uuid.UUID, scopes []string) (bool, error) {
	record, err := s.repos.Consent.GetByUserAndClient(ctx, tenantID, userID, clientID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("get consent: %w", err)
	}
	if record.ExpiresAt != nil && time.Now().After(*record.ExpiresAt) {
		return false, nil
	}
	consented := make(map[string]bool, len(record.Scopes))
	for _, sc := range record.Scopes {
		consented[sc] = true
	}
	for _, requested := range scopes {
		if !consented[requested] {
			return false, nil
		}
	}
	return true, nil
}

func (s *consentServiceImpl) GrantConsent(ctx context.Context, tenantID, userID, clientID uuid.UUID, scopes []string, expiresAt *time.Time) error {
	consent := &models.ConsentRecord{
		TenantID:  tenantID,
		UserID:    userID,
		ClientID:  clientID,
		Scopes:    models.StringArray(scopes),
		ExpiresAt: expiresAt,
	}
	if err := s.repos.Consent.Upsert(ctx, consent); err != nil {
		return fmt.Errorf("grant consent: %w", err)
	}
	s.logger.WithFields(logrus.Fields{
		"tenant_id": tenantID,
		"user_id":   userID,
		"client_id": clientID,
		"scopes":    scopes,
	}).Info("consent granted")
	return nil
}

func (s *consentServiceImpl) RevokeConsent(ctx context.Context, tenantID, userID, clientID uuid.UUID) error {
	if err := s.repos.Consent.Delete(ctx, tenantID, userID, clientID); err != nil {
		return fmt.Errorf("revoke consent: %w", err)
	}
	s.logger.WithFields(logrus.Fields{
		"tenant_id": tenantID,
		"user_id":   userID,
		"client_id": clientID,
	}).Info("consent revoked")
	return nil
}

func (s *consentServiceImpl) ListConsents(ctx context.Context, tenantID, userID uuid.UUID) ([]*models.ConsentRecord, error) {
	records, err := s.repos.Consent.ListByUser(ctx, tenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("list consents: %w", err)
	}
	return records, nil
}
