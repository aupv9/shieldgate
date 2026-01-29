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

type clientRepository struct {
	db *gorm.DB
}

// NewClientRepository creates a new client repository
func NewClientRepository(db *gorm.DB) repo.ClientRepository {
	return &clientRepository{db: db}
}

func (r *clientRepository) Create(ctx context.Context, client *models.Client) error {
	if err := r.db.WithContext(ctx).Create(client).Error; err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}
	return nil
}

func (r *clientRepository) GetByID(ctx context.Context, tenantID, clientID uuid.UUID) (*models.Client, error) {
	var client models.Client
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND id = ?", tenantID, clientID).
		First(&client).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, models.ErrClientNotFound
		}
		return nil, fmt.Errorf("failed to get client by ID: %w", err)
	}
	return &client, nil
}

func (r *clientRepository) GetByClientID(ctx context.Context, tenantID uuid.UUID, clientID string) (*models.Client, error) {
	var client models.Client
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND client_id = ?", tenantID, clientID).
		First(&client).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, models.ErrClientNotFound
		}
		return nil, fmt.Errorf("failed to get client by client_id: %w", err)
	}
	return &client, nil
}

func (r *clientRepository) Update(ctx context.Context, client *models.Client) error {
	if err := r.db.WithContext(ctx).Save(client).Error; err != nil {
		return fmt.Errorf("failed to update client: %w", err)
	}
	return nil
}

func (r *clientRepository) Delete(ctx context.Context, tenantID, clientID uuid.UUID) error {
	if err := r.db.WithContext(ctx).
		Delete(&models.Client{}, "tenant_id = ? AND id = ?", tenantID, clientID).Error; err != nil {
		return fmt.Errorf("failed to delete client: %w", err)
	}
	return nil
}

func (r *clientRepository) List(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]*models.Client, int64, error) {
	var clients []*models.Client
	var total int64

	// Get total count for tenant
	if err := r.db.WithContext(ctx).
		Model(&models.Client{}).
		Where("tenant_id = ?", tenantID).
		Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to count clients: %w", err)
	}

	// Get paginated results for tenant
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ?", tenantID).
		Order("created_at DESC").
		Limit(limit).
		Offset(offset).
		Find(&clients).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to list clients: %w", err)
	}

	return clients, total, nil
}
