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

type userRoleRepository struct {
	db *gorm.DB
}

// NewUserRoleRepository creates a new user-role repository
func NewUserRoleRepository(db *gorm.DB) repo.UserRoleRepository {
	return &userRoleRepository{db: db}
}

func (r *userRoleRepository) Create(ctx context.Context, userRole *models.UserRole) error {
	if err := r.db.WithContext(ctx).Create(userRole).Error; err != nil {
		return fmt.Errorf("failed to create user role: %w", err)
	}
	return nil
}

func (r *userRoleRepository) GetByID(ctx context.Context, tenantID, userRoleID uuid.UUID) (*models.UserRole, error) {
	var userRole models.UserRole
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND id = ?", tenantID, userRoleID).
		First(&userRole).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, models.ErrRoleNotFound
		}
		return nil, fmt.Errorf("failed to get user role: %w", err)
	}
	return &userRole, nil
}

func (r *userRoleRepository) GetByUserAndRole(ctx context.Context, tenantID, userID, roleID uuid.UUID) (*models.UserRole, error) {
	var userRole models.UserRole
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND user_id = ? AND role_id = ?", tenantID, userID, roleID).
		First(&userRole).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, models.ErrRoleNotFound
		}
		return nil, fmt.Errorf("failed to get user role assignment: %w", err)
	}
	return &userRole, nil
}

func (r *userRoleRepository) Delete(ctx context.Context, tenantID, userID, roleID uuid.UUID) error {
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND user_id = ? AND role_id = ?", tenantID, userID, roleID).
		Delete(&models.UserRole{}).Error; err != nil {
		return fmt.Errorf("failed to delete user role: %w", err)
	}
	return nil
}

func (r *userRoleRepository) GetUserRoles(ctx context.Context, tenantID, userID uuid.UUID) ([]*models.UserRole, error) {
	var userRoles []*models.UserRole
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND user_id = ?", tenantID, userID).
		Find(&userRoles).Error; err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}
	return userRoles, nil
}

func (r *userRoleRepository) GetRoleUsers(ctx context.Context, tenantID, roleID uuid.UUID) ([]*models.UserRole, error) {
	var userRoles []*models.UserRole
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND role_id = ?", tenantID, roleID).
		Find(&userRoles).Error; err != nil {
		return nil, fmt.Errorf("failed to get role users: %w", err)
	}
	return userRoles, nil
}

func (r *userRoleRepository) DeleteExpired(ctx context.Context) error {
	if err := r.db.WithContext(ctx).
		Where("expires_at IS NOT NULL AND expires_at < ?", time.Now()).
		Delete(&models.UserRole{}).Error; err != nil {
		return fmt.Errorf("failed to delete expired user roles: %w", err)
	}
	return nil
}
