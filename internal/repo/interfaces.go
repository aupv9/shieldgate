package repo

import (
	"context"

	"shieldgate/internal/models"

	"github.com/google/uuid"
)

// TenantRepository defines the interface for tenant data operations
type TenantRepository interface {
	Create(ctx context.Context, tenant *models.Tenant) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.Tenant, error)
	GetByDomain(ctx context.Context, domain string) (*models.Tenant, error)
	Update(ctx context.Context, tenant *models.Tenant) error
	Delete(ctx context.Context, id uuid.UUID) error
	List(ctx context.Context, limit, offset int) ([]*models.Tenant, int64, error)
}

// UserRepository defines the interface for user data operations
type UserRepository interface {
	Create(ctx context.Context, user *models.User) error
	GetByID(ctx context.Context, tenantID, userID uuid.UUID) (*models.User, error)
	GetByEmail(ctx context.Context, tenantID uuid.UUID, email string) (*models.User, error)
	GetByUsername(ctx context.Context, tenantID uuid.UUID, username string) (*models.User, error)
	Update(ctx context.Context, user *models.User) error
	Delete(ctx context.Context, tenantID, userID uuid.UUID) error
	List(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]*models.User, int64, error)
}

// ClientRepository defines the interface for client data operations
type ClientRepository interface {
	Create(ctx context.Context, client *models.Client) error
	GetByID(ctx context.Context, tenantID, clientID uuid.UUID) (*models.Client, error)
	GetByClientID(ctx context.Context, tenantID uuid.UUID, clientID string) (*models.Client, error)
	Update(ctx context.Context, client *models.Client) error
	Delete(ctx context.Context, tenantID, clientID uuid.UUID) error
	List(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]*models.Client, int64, error)
}

// AuthCodeRepository defines the interface for authorization code data operations
type AuthCodeRepository interface {
	Create(ctx context.Context, code *models.AuthorizationCode) error
	GetByCode(ctx context.Context, tenantID uuid.UUID, code string) (*models.AuthorizationCode, error)
	Delete(ctx context.Context, tenantID uuid.UUID, code string) error
	DeleteExpired(ctx context.Context) error
}

// AccessTokenRepository defines the interface for access token data operations
type AccessTokenRepository interface {
	Create(ctx context.Context, token *models.AccessToken) error
	GetByToken(ctx context.Context, tenantID uuid.UUID, token string) (*models.AccessToken, error)
	Delete(ctx context.Context, tenantID uuid.UUID, token string) error
	DeleteExpired(ctx context.Context) error
	DeleteByUserID(ctx context.Context, tenantID, userID uuid.UUID) error
}

// RefreshTokenRepository defines the interface for refresh token data operations
type RefreshTokenRepository interface {
	Create(ctx context.Context, token *models.RefreshToken) error
	GetByToken(ctx context.Context, tenantID uuid.UUID, token string) (*models.RefreshToken, error)
	Delete(ctx context.Context, tenantID uuid.UUID, token string) error
	DeleteExpired(ctx context.Context) error
	DeleteByUserID(ctx context.Context, tenantID, userID uuid.UUID) error
}

// Repositories aggregates all repository interfaces
type Repositories struct {
	Tenant       TenantRepository
	User         UserRepository
	Client       ClientRepository
	AuthCode     AuthCodeRepository
	AccessToken  AccessTokenRepository
	RefreshToken RefreshTokenRepository
}
