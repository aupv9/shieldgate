package services

import (
	"context"

	"shieldgate/internal/models"

	"github.com/google/uuid"
)

// TenantService defines the interface for tenant business logic
type TenantService interface {
	Create(ctx context.Context, req *models.CreateTenantRequest) (*models.Tenant, error)
	GetByID(ctx context.Context, id uuid.UUID) (*models.Tenant, error)
	GetByDomain(ctx context.Context, domain string) (*models.Tenant, error)
	Update(ctx context.Context, id uuid.UUID, req *models.UpdateTenantRequest) (*models.Tenant, error)
	Delete(ctx context.Context, id uuid.UUID) error
	List(ctx context.Context, limit, offset int) (*models.PaginatedResponse, error)
}

// UserService defines the interface for user business logic
type UserService interface {
	Create(ctx context.Context, tenantID uuid.UUID, req *models.CreateUserRequest) (*models.User, error)
	GetByID(ctx context.Context, tenantID, userID uuid.UUID) (*models.User, error)
	GetByEmail(ctx context.Context, tenantID uuid.UUID, email string) (*models.User, error)
	GetByUsername(ctx context.Context, tenantID uuid.UUID, username string) (*models.User, error)
	Update(ctx context.Context, tenantID, userID uuid.UUID, req *models.UpdateUserRequest) (*models.User, error)
	Delete(ctx context.Context, tenantID, userID uuid.UUID) error
	List(ctx context.Context, tenantID uuid.UUID, limit, offset int) (*models.PaginatedResponse, error)
	Authenticate(ctx context.Context, tenantID uuid.UUID, email, password string) (*models.User, error)
	ChangePassword(ctx context.Context, tenantID, userID uuid.UUID, oldPassword, newPassword string) error
}

// ClientService defines the interface for OAuth client business logic
type ClientService interface {
	Create(ctx context.Context, tenantID uuid.UUID, req *models.CreateClientRequest) (*models.Client, error)
	GetByID(ctx context.Context, tenantID, clientID uuid.UUID) (*models.Client, error)
	GetByClientID(ctx context.Context, tenantID uuid.UUID, clientID string) (*models.Client, error)
	Update(ctx context.Context, tenantID, clientID uuid.UUID, req *models.UpdateClientRequest) (*models.Client, error)
	Delete(ctx context.Context, tenantID, clientID uuid.UUID) error
	List(ctx context.Context, tenantID uuid.UUID, limit, offset int) (*models.PaginatedResponse, error)
	ValidateClient(ctx context.Context, tenantID uuid.UUID, clientID, clientSecret string) (*models.Client, error)
	ValidateRedirectURI(ctx context.Context, client *models.Client, redirectURI string) error
}

// AuthService defines the interface for OAuth authentication business logic
type AuthService interface {
	// Authorization Code Flow
	GenerateAuthorizationCode(ctx context.Context, tenantID, clientID, userID uuid.UUID, redirectURI, scope, codeChallenge, codeChallengeMethod string) (*models.AuthorizationCode, error)
	ExchangeAuthorizationCode(ctx context.Context, tenantID uuid.UUID, code, clientID, clientSecret, redirectURI, codeVerifier string) (*models.TokenResponse, error)

	// Token Management
	GenerateTokens(ctx context.Context, tenantID, clientID, userID uuid.UUID, scope string, includeIDToken bool) (*models.TokenResponse, error)
	RefreshTokens(ctx context.Context, tenantID uuid.UUID, refreshToken, clientID, clientSecret string) (*models.TokenResponse, error)
	RevokeToken(ctx context.Context, tenantID uuid.UUID, token, tokenTypeHint string) error
	IntrospectToken(ctx context.Context, tenantID uuid.UUID, token string) (*models.IntrospectionResponse, error)

	// Token Validation
	ValidateAccessToken(ctx context.Context, tenantID uuid.UUID, token string) (*models.JWTClaims, error)
	ValidatePKCE(codeVerifier, codeChallenge, method string) bool

	// OpenID Connect
	GenerateIDToken(ctx context.Context, user *models.User, clientID string) (string, error)
	GetUserInfo(ctx context.Context, tenantID uuid.UUID, accessToken string) (*models.UserInfo, error)
	GetDiscoveryDocument(ctx context.Context) (*models.OpenIDConfiguration, error)

	// Cleanup
	CleanupExpiredTokens(ctx context.Context) error
}

// Services aggregates all service interfaces
type Services struct {
	Tenant TenantService
	User   UserService
	Client ClientService
	Auth   AuthService
}
