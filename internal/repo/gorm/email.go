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

// ─── EmailTemplate Repository ────────────────────────────────────────────────

type emailTemplateRepository struct {
	db *gorm.DB
}

// NewEmailTemplateRepository creates a new email template repository
func NewEmailTemplateRepository(db *gorm.DB) repo.EmailTemplateRepository {
	return &emailTemplateRepository{db: db}
}

func (r *emailTemplateRepository) Create(ctx context.Context, template *models.EmailTemplate) error {
	if err := r.db.WithContext(ctx).Create(template).Error; err != nil {
		return fmt.Errorf("failed to create email template: %w", err)
	}
	return nil
}

func (r *emailTemplateRepository) GetByName(ctx context.Context, tenantID uuid.UUID, name string) (*models.EmailTemplate, error) {
	var template models.EmailTemplate
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND name = ?", tenantID, name).
		First(&template).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, models.ErrResourceNotFound
		}
		return nil, fmt.Errorf("failed to get email template: %w", err)
	}
	return &template, nil
}

func (r *emailTemplateRepository) Update(ctx context.Context, template *models.EmailTemplate) error {
	if err := r.db.WithContext(ctx).Save(template).Error; err != nil {
		return fmt.Errorf("failed to update email template: %w", err)
	}
	return nil
}

func (r *emailTemplateRepository) Delete(ctx context.Context, tenantID uuid.UUID, name string) error {
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND name = ?", tenantID, name).
		Delete(&models.EmailTemplate{}).Error; err != nil {
		return fmt.Errorf("failed to delete email template: %w", err)
	}
	return nil
}

func (r *emailTemplateRepository) List(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]*models.EmailTemplate, int64, error) {
	var templates []*models.EmailTemplate
	var total int64

	if err := r.db.WithContext(ctx).
		Model(&models.EmailTemplate{}).
		Where("tenant_id = ?", tenantID).
		Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to count email templates: %w", err)
	}

	if err := r.db.WithContext(ctx).
		Where("tenant_id = ?", tenantID).
		Order("name ASC").
		Limit(limit).
		Offset(offset).
		Find(&templates).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to list email templates: %w", err)
	}

	return templates, total, nil
}

// ─── EmailQueue Repository ────────────────────────────────────────────────────

type emailQueueRepository struct {
	db *gorm.DB
}

// NewEmailQueueRepository creates a new email queue repository
func NewEmailQueueRepository(db *gorm.DB) repo.EmailQueueRepository {
	return &emailQueueRepository{db: db}
}

func (r *emailQueueRepository) Create(ctx context.Context, email *models.EmailQueue) error {
	if err := r.db.WithContext(ctx).Create(email).Error; err != nil {
		return fmt.Errorf("failed to create email queue entry: %w", err)
	}
	return nil
}

func (r *emailQueueRepository) GetByID(ctx context.Context, tenantID, emailID uuid.UUID) (*models.EmailQueue, error) {
	var email models.EmailQueue
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND id = ?", tenantID, emailID).
		First(&email).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, models.ErrResourceNotFound
		}
		return nil, fmt.Errorf("failed to get email queue entry: %w", err)
	}
	return &email, nil
}

func (r *emailQueueRepository) GetPendingEmails(ctx context.Context, limit int) ([]*models.EmailQueue, error) {
	var emails []*models.EmailQueue
	if err := r.db.WithContext(ctx).
		Where("status = 'pending' AND scheduled_at <= ?", time.Now()).
		Order("priority ASC, scheduled_at ASC").
		Limit(limit).
		Find(&emails).Error; err != nil {
		return nil, fmt.Errorf("failed to get pending emails: %w", err)
	}
	return emails, nil
}

func (r *emailQueueRepository) Update(ctx context.Context, email *models.EmailQueue) error {
	if err := r.db.WithContext(ctx).Save(email).Error; err != nil {
		return fmt.Errorf("failed to update email queue entry: %w", err)
	}
	return nil
}

func (r *emailQueueRepository) Delete(ctx context.Context, tenantID, emailID uuid.UUID) error {
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND id = ?", tenantID, emailID).
		Delete(&models.EmailQueue{}).Error; err != nil {
		return fmt.Errorf("failed to delete email queue entry: %w", err)
	}
	return nil
}

func (r *emailQueueRepository) GetQueueStatus(ctx context.Context, tenantID uuid.UUID) (map[string]int, error) {
	type statusCount struct {
		Status string
		Count  int
	}
	var results []statusCount

	if err := r.db.WithContext(ctx).
		Model(&models.EmailQueue{}).
		Select("status, COUNT(*) as count").
		Where("tenant_id = ?", tenantID).
		Group("status").
		Scan(&results).Error; err != nil {
		return nil, fmt.Errorf("failed to get email queue status: %w", err)
	}

	status := make(map[string]int)
	for _, r := range results {
		status[r.Status] = r.Count
	}
	return status, nil
}

func (r *emailQueueRepository) GetFailedEmails(ctx context.Context, tenantID uuid.UUID, maxAttempts int) ([]*models.EmailQueue, error) {
	var emails []*models.EmailQueue
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND status = 'failed' AND attempts < ?", tenantID, maxAttempts).
		Order("created_at ASC").
		Find(&emails).Error; err != nil {
		return nil, fmt.Errorf("failed to get failed emails: %w", err)
	}
	return emails, nil
}

// ─── EmailVerification Repository ────────────────────────────────────────────

type emailVerificationRepository struct {
	db *gorm.DB
}

// NewEmailVerificationRepository creates a new email verification repository
func NewEmailVerificationRepository(db *gorm.DB) repo.EmailVerificationRepository {
	return &emailVerificationRepository{db: db}
}

func (r *emailVerificationRepository) Create(ctx context.Context, verification *models.EmailVerification) error {
	if err := r.db.WithContext(ctx).Create(verification).Error; err != nil {
		return fmt.Errorf("failed to create email verification: %w", err)
	}
	return nil
}

func (r *emailVerificationRepository) GetByCode(ctx context.Context, tenantID uuid.UUID, code string) (*models.EmailVerification, error) {
	var verification models.EmailVerification
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND code = ?", tenantID, code).
		First(&verification).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, models.ErrInvalidVerificationCode
		}
		return nil, fmt.Errorf("failed to get email verification by code: %w", err)
	}
	return &verification, nil
}

func (r *emailVerificationRepository) GetByUserID(ctx context.Context, tenantID, userID uuid.UUID) (*models.EmailVerification, error) {
	var verification models.EmailVerification
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND user_id = ? AND verified_at IS NULL", tenantID, userID).
		Order("created_at DESC").
		First(&verification).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, models.ErrResourceNotFound
		}
		return nil, fmt.Errorf("failed to get email verification by user ID: %w", err)
	}
	return &verification, nil
}

func (r *emailVerificationRepository) Update(ctx context.Context, verification *models.EmailVerification) error {
	if err := r.db.WithContext(ctx).Save(verification).Error; err != nil {
		return fmt.Errorf("failed to update email verification: %w", err)
	}
	return nil
}

func (r *emailVerificationRepository) Delete(ctx context.Context, tenantID uuid.UUID, code string) error {
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND code = ?", tenantID, code).
		Delete(&models.EmailVerification{}).Error; err != nil {
		return fmt.Errorf("failed to delete email verification: %w", err)
	}
	return nil
}

func (r *emailVerificationRepository) DeleteExpired(ctx context.Context) error {
	if err := r.db.WithContext(ctx).
		Where("expires_at < ? AND verified_at IS NULL", time.Now()).
		Delete(&models.EmailVerification{}).Error; err != nil {
		return fmt.Errorf("failed to delete expired email verifications: %w", err)
	}
	return nil
}

// ─── PasswordReset Repository ────────────────────────────────────────────────

type passwordResetRepository struct {
	db *gorm.DB
}

// NewPasswordResetRepository creates a new password reset repository
func NewPasswordResetRepository(db *gorm.DB) repo.PasswordResetRepository {
	return &passwordResetRepository{db: db}
}

func (r *passwordResetRepository) Create(ctx context.Context, reset *models.PasswordReset) error {
	if err := r.db.WithContext(ctx).Create(reset).Error; err != nil {
		return fmt.Errorf("failed to create password reset: %w", err)
	}
	return nil
}

func (r *passwordResetRepository) GetByToken(ctx context.Context, tenantID uuid.UUID, token string) (*models.PasswordReset, error) {
	var reset models.PasswordReset
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND token = ?", tenantID, token).
		First(&reset).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, models.ErrResourceNotFound
		}
		return nil, fmt.Errorf("failed to get password reset by token: %w", err)
	}
	return &reset, nil
}

func (r *passwordResetRepository) GetByUserID(ctx context.Context, tenantID, userID uuid.UUID) ([]*models.PasswordReset, error) {
	var resets []*models.PasswordReset
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND user_id = ?", tenantID, userID).
		Order("created_at DESC").
		Find(&resets).Error; err != nil {
		return nil, fmt.Errorf("failed to get password resets by user ID: %w", err)
	}
	return resets, nil
}

func (r *passwordResetRepository) Update(ctx context.Context, reset *models.PasswordReset) error {
	if err := r.db.WithContext(ctx).Save(reset).Error; err != nil {
		return fmt.Errorf("failed to update password reset: %w", err)
	}
	return nil
}

func (r *passwordResetRepository) Delete(ctx context.Context, tenantID uuid.UUID, token string) error {
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND token = ?", tenantID, token).
		Delete(&models.PasswordReset{}).Error; err != nil {
		return fmt.Errorf("failed to delete password reset: %w", err)
	}
	return nil
}

func (r *passwordResetRepository) DeleteExpired(ctx context.Context) error {
	if err := r.db.WithContext(ctx).
		Where("expires_at < ? AND used_at IS NULL", time.Now()).
		Delete(&models.PasswordReset{}).Error; err != nil {
		return fmt.Errorf("failed to delete expired password resets: %w", err)
	}
	return nil
}
