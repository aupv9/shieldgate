package repo

import (
	"context"

	"shieldgate/internal/models"

	"github.com/google/uuid"
)

// SocialAccountRepository manages user-linked social provider identities
type SocialAccountRepository interface {
	Create(ctx context.Context, account *models.SocialAccount) error
	GetByProviderAndExternalID(ctx context.Context, provider, externalID string) (*models.SocialAccount, error)
	GetByUserAndProvider(ctx context.Context, tenantID, userID uuid.UUID, provider string) (*models.SocialAccount, error)
	ListByUser(ctx context.Context, tenantID, userID uuid.UUID) ([]*models.SocialAccount, error)
	Update(ctx context.Context, account *models.SocialAccount) error
	Delete(ctx context.Context, tenantID, userID uuid.UUID, provider string) error
}

// SocialProviderRepository manages per-tenant social OAuth2 provider config
type SocialProviderRepository interface {
	Create(ctx context.Context, p *models.SocialProvider) error
	GetByTenantAndProvider(ctx context.Context, tenantID uuid.UUID, provider string) (*models.SocialProvider, error)
	List(ctx context.Context, tenantID uuid.UUID) ([]*models.SocialProvider, error)
	Update(ctx context.Context, p *models.SocialProvider) error
	Delete(ctx context.Context, tenantID uuid.UUID, provider string) error
}

// WebhookRepository manages webhook endpoints and delivery records
type WebhookRepository interface {
	Create(ctx context.Context, w *models.WebhookEndpoint) error
	GetByID(ctx context.Context, tenantID, webhookID uuid.UUID) (*models.WebhookEndpoint, error)
	Update(ctx context.Context, w *models.WebhookEndpoint) error
	Delete(ctx context.Context, tenantID, webhookID uuid.UUID) error
	List(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]*models.WebhookEndpoint, int64, error)
	ListActive(ctx context.Context, tenantID uuid.UUID, event string) ([]*models.WebhookEndpoint, error)
	CreateDelivery(ctx context.Context, d *models.WebhookDelivery) error
	ListDeliveries(ctx context.Context, tenantID, webhookID uuid.UUID, limit, offset int) ([]*models.WebhookDelivery, int64, error)
}

// APIKeyRepository manages API key lifecycle
type APIKeyRepository interface {
	Create(ctx context.Context, key *models.APIKey) error
	GetByID(ctx context.Context, tenantID, keyID uuid.UUID) (*models.APIKey, error)
	GetByHash(ctx context.Context, hash string) (*models.APIKey, error)
	List(ctx context.Context, tenantID uuid.UUID, userID *uuid.UUID, limit, offset int) ([]*models.APIKey, int64, error)
	Revoke(ctx context.Context, tenantID, keyID uuid.UUID) error
	UpdateLastUsed(ctx context.Context, keyID uuid.UUID) error
	Delete(ctx context.Context, tenantID, keyID uuid.UUID) error
}
