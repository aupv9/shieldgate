package gorm

import (
	"context"
	"time"

	"shieldgate/internal/models"
	"shieldgate/internal/repo"

	"gorm.io/gorm"
)

type blocklistRepository struct {
	db *gorm.DB
}

// NewBlocklistRepository creates a GORM-backed BlocklistRepository.
func NewBlocklistRepository(db *gorm.DB) repo.BlocklistRepository {
	return &blocklistRepository{db: db}
}

func (r *blocklistRepository) Add(ctx context.Context, entry *models.TokenBlocklist) error {
	return r.db.WithContext(ctx).Create(entry).Error
}

func (r *blocklistRepository) IsBlocked(ctx context.Context, jti string) (bool, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&models.TokenBlocklist{}).
		Where("jti = ? AND expires_at > ?", jti, time.Now()).
		Count(&count).Error
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (r *blocklistRepository) DeleteExpired(ctx context.Context) error {
	return r.db.WithContext(ctx).
		Where("expires_at <= ?", time.Now()).
		Delete(&models.TokenBlocklist{}).Error
}
