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
	"gorm.io/gorm/clause"
)

type sessionRepository struct {
	db *gorm.DB
}

// NewSessionRepository creates a new SSO session repository
func NewSessionRepository(db *gorm.DB) repo.SessionRepository {
	return &sessionRepository{db: db}
}

func (r *sessionRepository) Create(ctx context.Context, session *models.Session) error {
	if err := r.db.WithContext(ctx).Create(session).Error; err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}
	return nil
}

func (r *sessionRepository) GetByTokenHash(ctx context.Context, tenantID uuid.UUID, tokenHash string) (*models.Session, error) {
	var session models.Session
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND token_hash = ?", tenantID, tokenHash).
		First(&session).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, models.ErrSessionNotFound
		}
		return nil, fmt.Errorf("failed to get session: %w", err)
	}
	return &session, nil
}

func (r *sessionRepository) DeleteByTokenHash(ctx context.Context, tenantID uuid.UUID, tokenHash string) error {
	if err := r.db.WithContext(ctx).
		Delete(&models.Session{}, "tenant_id = ? AND token_hash = ?", tenantID, tokenHash).Error; err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}
	return nil
}

func (r *sessionRepository) DeleteByUserID(ctx context.Context, tenantID, userID uuid.UUID) error {
	if err := r.db.WithContext(ctx).
		Delete(&models.Session{}, "tenant_id = ? AND user_id = ?", tenantID, userID).Error; err != nil {
		return fmt.Errorf("failed to delete user sessions: %w", err)
	}
	return nil
}

func (r *sessionRepository) DeleteExpired(ctx context.Context) error {
	if err := r.db.WithContext(ctx).
		Delete(&models.Session{}, "expires_at < ?", time.Now()).Error; err != nil {
		return fmt.Errorf("failed to delete expired sessions: %w", err)
	}
	return nil
}

type consentRepository struct {
	db *gorm.DB
}

// NewConsentRepository creates a new consent repository
func NewConsentRepository(db *gorm.DB) repo.ConsentRepository {
	return &consentRepository{db: db}
}

func (r *consentRepository) Get(ctx context.Context, tenantID, userID, clientID uuid.UUID) (*models.Consent, error) {
	var consent models.Consent
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND user_id = ? AND client_id = ?", tenantID, userID, clientID).
		First(&consent).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, models.ErrResourceNotFound
		}
		return nil, fmt.Errorf("failed to get consent: %w", err)
	}
	return &consent, nil
}

// Upsert inserts the consent or replaces the scope of the existing record for
// the same (tenant, user, client)
func (r *consentRepository) Upsert(ctx context.Context, consent *models.Consent) error {
	if err := r.db.WithContext(ctx).
		Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "tenant_id"}, {Name: "user_id"}, {Name: "client_id"}},
			DoUpdates: clause.AssignmentColumns([]string{"scope", "updated_at"}),
		}).
		Create(consent).Error; err != nil {
		return fmt.Errorf("failed to save consent: %w", err)
	}
	return nil
}

func (r *consentRepository) Delete(ctx context.Context, tenantID, userID, clientID uuid.UUID) error {
	if err := r.db.WithContext(ctx).
		Delete(&models.Consent{}, "tenant_id = ? AND user_id = ? AND client_id = ?", tenantID, userID, clientID).Error; err != nil {
		return fmt.Errorf("failed to delete consent: %w", err)
	}
	return nil
}
