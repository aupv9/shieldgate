package repo

import (
	"context"

	"shieldgate/internal/models"

	"github.com/google/uuid"
)

// ConsentRepository manages OAuth2 user consent records.
type ConsentRepository interface {
	// Upsert creates or updates a consent record (matched by tenant+user+client).
	Upsert(ctx context.Context, consent *models.ConsentRecord) error
	GetByUserAndClient(ctx context.Context, tenantID, userID, clientID uuid.UUID) (*models.ConsentRecord, error)
	ListByUser(ctx context.Context, tenantID, userID uuid.UUID) ([]*models.ConsentRecord, error)
	Delete(ctx context.Context, tenantID, userID, clientID uuid.UUID) error
	DeleteExpired(ctx context.Context) error
}
