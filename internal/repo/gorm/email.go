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

// Email queue statuses
const (
	emailStatusPending = "pending"
	emailStatusSending = "sending"
	emailStatusFailed  = "failed"
)

// staleSendingAfter is how long an email may stay claimed before another
// worker reclaims it (the claiming worker presumably crashed)
const staleSendingAfter = 10 * time.Minute

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
		Delete(&models.EmailTemplate{}, "tenant_id = ? AND name = ?", tenantID, name).Error; err != nil {
		return fmt.Errorf("failed to delete email template: %w", err)
	}
	return nil
}

func (r *emailTemplateRepository) List(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]*models.EmailTemplate, int64, error) {
	var templates []*models.EmailTemplate
	var total int64
	query := r.db.WithContext(ctx).Model(&models.EmailTemplate{}).Where("tenant_id = ?", tenantID)
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to count email templates: %w", err)
	}
	if err := query.Order("name").Limit(limit).Offset(offset).Find(&templates).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to list email templates: %w", err)
	}
	return templates, total, nil
}

type emailQueueRepository struct {
	db *gorm.DB
}

// NewEmailQueueRepository creates a new email queue repository
func NewEmailQueueRepository(db *gorm.DB) repo.EmailQueueRepository {
	return &emailQueueRepository{db: db}
}

func (r *emailQueueRepository) Create(ctx context.Context, email *models.EmailQueue) error {
	if err := r.db.WithContext(ctx).Create(email).Error; err != nil {
		return fmt.Errorf("failed to queue email: %w", err)
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
		return nil, fmt.Errorf("failed to get email: %w", err)
	}
	return &email, nil
}

// GetPendingEmails atomically claims due emails. FOR UPDATE SKIP LOCKED lets
// several server replicas drain the queue without sending duplicates.
func (r *emailQueueRepository) GetPendingEmails(ctx context.Context, limit int) ([]*models.EmailQueue, error) {
	var emails []*models.EmailQueue
	now := time.Now()
	err := r.db.WithContext(ctx).Raw(`
		UPDATE email_queue SET status = ?, updated_at = ?
		WHERE id IN (
			SELECT id FROM email_queue
			WHERE (status = ? AND scheduled_at <= ?) OR (status = ? AND updated_at < ?)
			ORDER BY priority, scheduled_at
			LIMIT ?
			FOR UPDATE SKIP LOCKED
		)
		RETURNING *`,
		emailStatusSending, now,
		emailStatusPending, now, emailStatusSending, now.Add(-staleSendingAfter),
		limit,
	).Scan(&emails).Error
	if err != nil {
		return nil, fmt.Errorf("failed to claim pending emails: %w", err)
	}
	return emails, nil
}

func (r *emailQueueRepository) Update(ctx context.Context, email *models.EmailQueue) error {
	if err := r.db.WithContext(ctx).Omit("User").Save(email).Error; err != nil {
		return fmt.Errorf("failed to update email: %w", err)
	}
	return nil
}

func (r *emailQueueRepository) Delete(ctx context.Context, tenantID, emailID uuid.UUID) error {
	if err := r.db.WithContext(ctx).
		Delete(&models.EmailQueue{}, "tenant_id = ? AND id = ?", tenantID, emailID).Error; err != nil {
		return fmt.Errorf("failed to delete email: %w", err)
	}
	return nil
}

func (r *emailQueueRepository) GetQueueStatus(ctx context.Context, tenantID uuid.UUID) (map[string]int, error) {
	var rows []struct {
		Status string
		Count  int
	}
	if err := r.db.WithContext(ctx).Model(&models.EmailQueue{}).
		Select("status, COUNT(*) AS count").
		Where("tenant_id = ?", tenantID).
		Group("status").
		Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("failed to get email queue status: %w", err)
	}
	status := make(map[string]int, len(rows))
	for _, row := range rows {
		status[row.Status] = row.Count
	}
	return status, nil
}

func (r *emailQueueRepository) GetFailedEmails(ctx context.Context, tenantID uuid.UUID, maxAttempts int) ([]*models.EmailQueue, error) {
	var emails []*models.EmailQueue
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND status = ? AND attempts < ?", tenantID, emailStatusFailed, maxAttempts).
		Find(&emails).Error; err != nil {
		return nil, fmt.Errorf("failed to get failed emails: %w", err)
	}
	return emails, nil
}

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

func (r *emailVerificationRepository) GetByCodeHash(ctx context.Context, tenantID uuid.UUID, codeHash string) (*models.EmailVerification, error) {
	var verification models.EmailVerification
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND code_hash = ?", tenantID, codeHash).
		First(&verification).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, models.ErrInvalidVerificationCode
		}
		return nil, fmt.Errorf("failed to get email verification: %w", err)
	}
	return &verification, nil
}

func (r *emailVerificationRepository) MarkVerified(ctx context.Context, id uuid.UUID) (bool, error) {
	result := r.db.WithContext(ctx).Model(&models.EmailVerification{}).
		Where("id = ? AND verified_at IS NULL", id).
		Update("verified_at", time.Now())
	if result.Error != nil {
		return false, fmt.Errorf("failed to mark email verified: %w", result.Error)
	}
	return result.RowsAffected == 1, nil
}

func (r *emailVerificationRepository) DeletePendingByUserID(ctx context.Context, tenantID, userID uuid.UUID) error {
	if err := r.db.WithContext(ctx).
		Delete(&models.EmailVerification{}, "tenant_id = ? AND user_id = ? AND verified_at IS NULL", tenantID, userID).Error; err != nil {
		return fmt.Errorf("failed to delete pending email verifications: %w", err)
	}
	return nil
}

func (r *emailVerificationRepository) DeleteExpired(ctx context.Context) error {
	if err := r.db.WithContext(ctx).
		Delete(&models.EmailVerification{}, "expires_at < ?", time.Now()).Error; err != nil {
		return fmt.Errorf("failed to delete expired email verifications: %w", err)
	}
	return nil
}

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

func (r *passwordResetRepository) GetByTokenHash(ctx context.Context, tenantID uuid.UUID, tokenHash string) (*models.PasswordReset, error) {
	var reset models.PasswordReset
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND token_hash = ?", tenantID, tokenHash).
		First(&reset).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, models.ErrInvalidVerificationCode
		}
		return nil, fmt.Errorf("failed to get password reset: %w", err)
	}
	return &reset, nil
}

func (r *passwordResetRepository) MarkUsed(ctx context.Context, id uuid.UUID) (bool, error) {
	result := r.db.WithContext(ctx).Model(&models.PasswordReset{}).
		Where("id = ? AND used_at IS NULL", id).
		Update("used_at", time.Now())
	if result.Error != nil {
		return false, fmt.Errorf("failed to mark password reset used: %w", result.Error)
	}
	return result.RowsAffected == 1, nil
}

func (r *passwordResetRepository) CountSince(ctx context.Context, tenantID, userID uuid.UUID, since time.Time) (int64, error) {
	var count int64
	if err := r.db.WithContext(ctx).Model(&models.PasswordReset{}).
		Where("tenant_id = ? AND user_id = ? AND created_at > ?", tenantID, userID, since).
		Count(&count).Error; err != nil {
		return 0, fmt.Errorf("failed to count password resets: %w", err)
	}
	return count, nil
}

func (r *passwordResetRepository) RevokeUnusedByUserID(ctx context.Context, tenantID, userID uuid.UUID) error {
	if err := r.db.WithContext(ctx).Model(&models.PasswordReset{}).
		Where("tenant_id = ? AND user_id = ? AND used_at IS NULL", tenantID, userID).
		Update("used_at", time.Now()).Error; err != nil {
		return fmt.Errorf("failed to revoke unused password resets: %w", err)
	}
	return nil
}

// DeleteExpired keeps recent rows so CountSince can rate-limit requests
func (r *passwordResetRepository) DeleteExpired(ctx context.Context) error {
	if err := r.db.WithContext(ctx).
		Delete(&models.PasswordReset{}, "expires_at < ? AND created_at < ?", time.Now(), time.Now().Add(-24*time.Hour)).Error; err != nil {
		return fmt.Errorf("failed to delete expired password resets: %w", err)
	}
	return nil
}
