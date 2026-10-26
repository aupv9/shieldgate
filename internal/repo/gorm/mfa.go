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

type mfaRepository struct {
	db *gorm.DB
}

// NewMFARepository creates a new MFA repository
func NewMFARepository(db *gorm.DB) repo.MFARepository {
	return &mfaRepository{db: db}
}

func (r *mfaRepository) Get(ctx context.Context, tenantID, userID uuid.UUID) (*models.UserMFA, error) {
	var mfa models.UserMFA
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND user_id = ?", tenantID, userID).
		First(&mfa).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, models.ErrMFANotEnabled
		}
		return nil, fmt.Errorf("failed to get MFA settings: %w", err)
	}
	return &mfa, nil
}

func (r *mfaRepository) SavePending(ctx context.Context, mfa *models.UserMFA) error {
	now := time.Now()
	mfa.ConfirmedAt = nil
	mfa.CreatedAt, mfa.UpdatedAt = now, now
	// Only an unconfirmed row may be replaced; a confirmed authenticator
	// must be disabled first
	result := r.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "user_id"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"totp_secret", "last_used_step", "failed_attempts", "locked_until", "created_at", "updated_at",
		}),
		Where: clause.Where{Exprs: []clause.Expression{
			clause.Expr{SQL: "user_mfa.confirmed_at IS NULL AND user_mfa.tenant_id = ?", Vars: []interface{}{mfa.TenantID}},
		}},
	}).Create(mfa)
	if result.Error != nil {
		return fmt.Errorf("failed to save MFA enrollment: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return models.ErrMFAAlreadyEnabled
	}
	return nil
}

func (r *mfaRepository) Confirm(ctx context.Context, tenantID, userID uuid.UUID, step int64, recoveryCodeHashes []string) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		result := tx.Model(&models.UserMFA{}).
			Where("tenant_id = ? AND user_id = ? AND confirmed_at IS NULL", tenantID, userID).
			Updates(map[string]interface{}{
				"confirmed_at":    time.Now(),
				"last_used_step":  step,
				"failed_attempts": 0,
				"locked_until":    nil,
				"updated_at":      time.Now(),
			})
		if result.Error != nil {
			return fmt.Errorf("failed to confirm MFA enrollment: %w", result.Error)
		}
		if result.RowsAffected == 0 {
			return models.ErrMFANotEnrolling
		}
		return replaceRecoveryCodes(tx, tenantID, userID, recoveryCodeHashes)
	})
}

func (r *mfaRepository) UseStep(ctx context.Context, tenantID, userID uuid.UUID, step int64) (bool, error) {
	result := r.db.WithContext(ctx).Model(&models.UserMFA{}).
		Where("tenant_id = ? AND user_id = ? AND confirmed_at IS NOT NULL AND last_used_step < ?", tenantID, userID, step).
		Updates(map[string]interface{}{
			"last_used_step":  step,
			"failed_attempts": 0,
			"locked_until":    nil,
			"updated_at":      time.Now(),
		})
	if result.Error != nil {
		return false, fmt.Errorf("failed to record TOTP use: %w", result.Error)
	}
	return result.RowsAffected == 1, nil
}

func (r *mfaRepository) UseRecoveryCode(ctx context.Context, tenantID, userID uuid.UUID, codeHash string) (bool, error) {
	used := false
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		result := tx.Model(&models.MFARecoveryCode{}).
			Where("tenant_id = ? AND user_id = ? AND code_hash = ? AND used_at IS NULL", tenantID, userID, codeHash).
			Update("used_at", time.Now())
		if result.Error != nil {
			return fmt.Errorf("failed to use recovery code: %w", result.Error)
		}
		if result.RowsAffected == 0 {
			return nil
		}
		used = true
		return tx.Model(&models.UserMFA{}).
			Where("tenant_id = ? AND user_id = ?", tenantID, userID).
			Updates(map[string]interface{}{"failed_attempts": 0, "locked_until": nil, "updated_at": time.Now()}).Error
	})
	return used, err
}

func (r *mfaRepository) RecordFailure(ctx context.Context, tenantID, userID uuid.UUID, maxFailures int, lockUntil time.Time) error {
	if err := r.db.WithContext(ctx).Model(&models.UserMFA{}).
		Where("tenant_id = ? AND user_id = ?", tenantID, userID).
		Updates(map[string]interface{}{
			"failed_attempts": gorm.Expr("failed_attempts + 1"),
			"locked_until":    gorm.Expr("CASE WHEN failed_attempts + 1 >= ? THEN ?::timestamptz ELSE locked_until END", maxFailures, lockUntil),
			"updated_at":      time.Now(),
		}).Error; err != nil {
		return fmt.Errorf("failed to record MFA failure: %w", err)
	}
	return nil
}

func (r *mfaRepository) ReplaceRecoveryCodes(ctx context.Context, tenantID, userID uuid.UUID, codeHashes []string) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return replaceRecoveryCodes(tx, tenantID, userID, codeHashes)
	})
}

func replaceRecoveryCodes(tx *gorm.DB, tenantID, userID uuid.UUID, codeHashes []string) error {
	if err := tx.Delete(&models.MFARecoveryCode{}, "tenant_id = ? AND user_id = ?", tenantID, userID).Error; err != nil {
		return fmt.Errorf("failed to delete recovery codes: %w", err)
	}
	if len(codeHashes) == 0 {
		return nil
	}
	codes := make([]models.MFARecoveryCode, len(codeHashes))
	now := time.Now()
	for i, hash := range codeHashes {
		codes[i] = models.MFARecoveryCode{ID: uuid.New(), TenantID: tenantID, UserID: userID, CodeHash: hash, CreatedAt: now}
	}
	if err := tx.Create(&codes).Error; err != nil {
		return fmt.Errorf("failed to store recovery codes: %w", err)
	}
	return nil
}

func (r *mfaRepository) CountUnusedRecoveryCodes(ctx context.Context, tenantID, userID uuid.UUID) (int64, error) {
	var count int64
	if err := r.db.WithContext(ctx).Model(&models.MFARecoveryCode{}).
		Where("tenant_id = ? AND user_id = ? AND used_at IS NULL", tenantID, userID).
		Count(&count).Error; err != nil {
		return 0, fmt.Errorf("failed to count recovery codes: %w", err)
	}
	return count, nil
}

func (r *mfaRepository) Delete(ctx context.Context, tenantID, userID uuid.UUID) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Delete(&models.MFARecoveryCode{}, "tenant_id = ? AND user_id = ?", tenantID, userID).Error; err != nil {
			return fmt.Errorf("failed to delete recovery codes: %w", err)
		}
		if err := tx.Delete(&models.UserMFA{}, "tenant_id = ? AND user_id = ?", tenantID, userID).Error; err != nil {
			return fmt.Errorf("failed to delete MFA settings: %w", err)
		}
		return nil
	})
}
