package gorm

import (
	"context"
	"errors"
	"fmt"
	"time"

	"shieldgate/internal/models"
	"shieldgate/internal/repo"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// --- sessions ---

type sessionRepository struct {
	db *gorm.DB
}

// NewSessionRepository creates a new user session repository
func NewSessionRepository(db *gorm.DB) repo.SessionRepository {
	return &sessionRepository{db: db}
}

func (r *sessionRepository) Create(ctx context.Context, session *models.UserSession) error {
	if err := r.db.WithContext(ctx).Create(session).Error; err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}
	return nil
}

func (r *sessionRepository) GetByToken(ctx context.Context, tenantID uuid.UUID, token string) (*models.UserSession, error) {
	var session models.UserSession
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND token = ?", tenantID, token).
		First(&session).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, models.ErrSessionNotFound
		}
		return nil, fmt.Errorf("failed to get session: %w", err)
	}
	return &session, nil
}

func (r *sessionRepository) Revoke(ctx context.Context, tenantID uuid.UUID, token string) error {
	if err := r.db.WithContext(ctx).
		Model(&models.UserSession{}).
		Where("tenant_id = ? AND token = ? AND revoked_at IS NULL", tenantID, token).
		Update("revoked_at", time.Now()).Error; err != nil {
		return fmt.Errorf("failed to revoke session: %w", err)
	}
	return nil
}

func (r *sessionRepository) RevokeByUserID(ctx context.Context, tenantID, userID uuid.UUID) error {
	if err := r.db.WithContext(ctx).
		Model(&models.UserSession{}).
		Where("tenant_id = ? AND user_id = ? AND revoked_at IS NULL", tenantID, userID).
		Update("revoked_at", time.Now()).Error; err != nil {
		return fmt.Errorf("failed to revoke sessions by user: %w", err)
	}
	return nil
}

func (r *sessionRepository) DeleteExpired(ctx context.Context) error {
	if err := r.db.WithContext(ctx).
		Delete(&models.UserSession{}, "expires_at < ?", time.Now()).Error; err != nil {
		return fmt.Errorf("failed to delete expired sessions: %w", err)
	}
	return nil
}

// --- consents ---

type consentRepository struct {
	db *gorm.DB
}

// NewConsentRepository creates a new user consent repository
func NewConsentRepository(db *gorm.DB) repo.ConsentRepository {
	return &consentRepository{db: db}
}

func (r *consentRepository) Create(ctx context.Context, consent *models.UserConsent) error {
	if err := r.db.WithContext(ctx).Create(consent).Error; err != nil {
		return fmt.Errorf("failed to create consent: %w", err)
	}
	return nil
}

func (r *consentRepository) ListByUserAndClient(ctx context.Context, tenantID, userID, clientID uuid.UUID) ([]*models.UserConsent, error) {
	var consents []*models.UserConsent
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND user_id = ? AND client_id = ? AND revoked_at IS NULL", tenantID, userID, clientID).
		Find(&consents).Error; err != nil {
		return nil, fmt.Errorf("failed to list consents: %w", err)
	}
	return consents, nil
}

func (r *consentRepository) RevokeByUserAndClient(ctx context.Context, tenantID, userID, clientID uuid.UUID) error {
	if err := r.db.WithContext(ctx).
		Model(&models.UserConsent{}).
		Where("tenant_id = ? AND user_id = ? AND client_id = ? AND revoked_at IS NULL", tenantID, userID, clientID).
		Update("revoked_at", time.Now()).Error; err != nil {
		return fmt.Errorf("failed to revoke consents: %w", err)
	}
	return nil
}
