package gorm

import (
	"context"
	"errors"
	"fmt"

	"shieldgate/internal/models"
	"shieldgate/internal/repo"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type userRepository struct {
	db *gorm.DB
}

// NewUserRepository creates a new user repository
func NewUserRepository(db *gorm.DB) repo.UserRepository {
	return &userRepository{db: db}
}

func (r *userRepository) Create(ctx context.Context, user *models.User) error {
	if err := r.db.WithContext(ctx).Create(user).Error; err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}
	return nil
}

func (r *userRepository) GetByID(ctx context.Context, tenantID, userID uuid.UUID) (*models.User, error) {
	var user models.User
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND id = ?", tenantID, userID).
		First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, models.ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user by ID: %w", err)
	}
	return &user, nil
}

func (r *userRepository) GetByEmail(ctx context.Context, tenantID uuid.UUID, email string) (*models.User, error) {
	var user models.User
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND email = ?", tenantID, email).
		First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, models.ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}
	return &user, nil
}

func (r *userRepository) GetByUsername(ctx context.Context, tenantID uuid.UUID, username string) (*models.User, error) {
	var user models.User
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND username = ?", tenantID, username).
		First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, models.ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user by username: %w", err)
	}
	return &user, nil
}

func (r *userRepository) Update(ctx context.Context, user *models.User) error {
	if err := r.db.WithContext(ctx).Save(user).Error; err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}
	return nil
}

func (r *userRepository) Delete(ctx context.Context, tenantID, userID uuid.UUID) error {
	if err := r.db.WithContext(ctx).
		Delete(&models.User{}, "tenant_id = ? AND id = ?", tenantID, userID).Error; err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	return nil
}

func (r *userRepository) List(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]*models.User, int64, error) {
	var users []*models.User
	var total int64

	// Get total count for tenant
	if err := r.db.WithContext(ctx).
		Model(&models.User{}).
		Where("tenant_id = ?", tenantID).
		Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to count users: %w", err)
	}

	// Get paginated results for tenant
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ?", tenantID).
		Order("created_at DESC").
		Limit(limit).
		Offset(offset).
		Find(&users).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to list users: %w", err)
	}

	return users, total, nil
}
