package models

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Custom error types for business logic
var (
	ErrTenantNotFound          = errors.New("tenant not found")
	ErrUserNotFound            = errors.New("user not found")
	ErrClientNotFound          = errors.New("client not found")
	ErrAuthCodeNotFound        = errors.New("authorization code not found")
	ErrAccessTokenNotFound     = errors.New("access token not found")
	ErrRefreshTokenNotFound    = errors.New("refresh token not found")
	ErrInvalidCredentials      = errors.New("invalid credentials")
	ErrInvalidClient           = errors.New("invalid client")
	ErrInvalidGrant            = errors.New("invalid grant")
	ErrInvalidScope            = errors.New("invalid scope")
	ErrExpiredToken            = errors.New("token expired")
	ErrRevokedToken            = errors.New("token revoked")
	ErrInsufficientPermissions = errors.New("insufficient permissions")
	ErrTenantMismatch          = errors.New("tenant mismatch")
)

// Error codes for API responses
const (
	ErrorCodeResourceNotFound        = "RESOURCE_NOT_FOUND"
	ErrorCodeInvalidRequest          = "INVALID_REQUEST"
	ErrorCodeValidationFailed        = "VALIDATION_FAILED"
	ErrorCodeUnauthorized            = "UNAUTHORIZED"
	ErrorCodeTokenExpired            = "TOKEN_EXPIRED"
	ErrorCodeForbidden               = "FORBIDDEN"
	ErrorCodeInsufficientPermissions = "INSUFFICIENT_PERMISSIONS"
	ErrorCodeResourceConflict        = "RESOURCE_CONFLICT"
	ErrorCodeDuplicateResource       = "DUPLICATE_RESOURCE"
	ErrorCodeBusinessRuleViolation   = "BUSINESS_RULE_VIOLATION"
	ErrorCodeRateLimitExceeded       = "RATE_LIMIT_EXCEEDED"
	ErrorCodeInternalError           = "INTERNAL_ERROR"
)

// StringArray represents a PostgreSQL string array
type StringArray []string

// Value implements the driver.Valuer interface
func (a StringArray) Value() (driver.Value, error) {
	if a == nil {
		return nil, nil
	}
	return json.Marshal(a)
}

// Scan implements the sql.Scanner interface
func (a *StringArray) Scan(value interface{}) error {
	if value == nil {
		*a = nil
		return nil
	}

	switch v := value.(type) {
	case []byte:
		return json.Unmarshal(v, a)
	case string:
		return json.Unmarshal([]byte(v), a)
	default:
		return errors.New("cannot scan into StringArray")
	}
}

// Tenant represents a tenant in the multi-tenant system
type Tenant struct {
	ID        uuid.UUID      `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	Name      string         `json:"name" gorm:"not null;size:255"`
	Domain    string         `json:"domain" gorm:"uniqueIndex:idx_tenants_domain;not null;size:255"`
	IsActive  bool           `json:"is_active" gorm:"not null;default:true"`
	CreatedAt time.Time      `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt time.Time      `json:"updated_at" gorm:"autoUpdateTime"`
	DeletedAt gorm.DeletedAt `json:"-" gorm:"index"`
}

// User represents a user in the system
type User struct {
	ID           uuid.UUID      `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	TenantID     uuid.UUID      `json:"tenant_id" gorm:"type:uuid;not null;index:idx_users_tenant_id"`
	Username     string         `json:"username" gorm:"not null;size:255;index:idx_users_tenant_username,unique"`
	Email        string         `json:"email" gorm:"not null;size:255;index:idx_users_tenant_email,unique"`
	PasswordHash string         `json:"-" gorm:"not null;size:255"`
	CreatedAt    time.Time      `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt    time.Time      `json:"updated_at" gorm:"autoUpdateTime"`
	DeletedAt    gorm.DeletedAt `json:"-" gorm:"index"`
}

// Client represents an OAuth 2.0 client
type Client struct {
	ID           uuid.UUID      `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	TenantID     uuid.UUID      `json:"tenant_id" gorm:"type:uuid;not null;index:idx_clients_tenant_id"`
	ClientID     string         `json:"client_id" gorm:"not null;size:255;index:idx_clients_tenant_client_id,unique"`
	ClientSecret string         `json:"client_secret,omitempty" gorm:"size:255"`
	Name         string         `json:"name" gorm:"not null;size:255"`
	RedirectURIs StringArray    `json:"redirect_uris" gorm:"type:jsonb;not null;default:'[]'"`
	GrantTypes   StringArray    `json:"grant_types" gorm:"type:jsonb;not null;default:'[]'"`
	Scopes       StringArray    `json:"scopes" gorm:"type:jsonb;not null;default:'[]'"`
	IsPublic     bool           `json:"is_public" gorm:"not null;default:false"`
	CreatedAt    time.Time      `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt    time.Time      `json:"updated_at" gorm:"autoUpdateTime"`
	DeletedAt    gorm.DeletedAt `json:"-" gorm:"index"`
}

// AuthorizationCode represents an OAuth 2.0 authorization code
type AuthorizationCode struct {
	ID                  uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	TenantID            uuid.UUID `json:"tenant_id" gorm:"type:uuid;not null;index"`
	Code                string    `json:"code" gorm:"not null;size:255;uniqueIndex"`
	ClientID            uuid.UUID `json:"client_id" gorm:"type:uuid;not null;index"`
	UserID              uuid.UUID `json:"user_id" gorm:"type:uuid;not null;index"`
	RedirectURI         string    `json:"redirect_uri" gorm:"not null;size:255"`
	Scope               string    `json:"scope" gorm:"type:text"`
	CodeChallenge       string    `json:"code_challenge" gorm:"size:255"`
	CodeChallengeMethod string    `json:"code_challenge_method" gorm:"size:50"`
	ExpiresAt           time.Time `json:"expires_at" gorm:"not null;index"`
	CreatedAt           time.Time `json:"created_at" gorm:"autoCreateTime"`
}

// AccessToken represents an OAuth 2.0 access token
type AccessToken struct {
	ID        uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	TenantID  uuid.UUID `json:"tenant_id" gorm:"type:uuid;not null;index"`
	Token     string    `json:"token" gorm:"not null;size:255;uniqueIndex"`
	ClientID  uuid.UUID `json:"client_id" gorm:"type:uuid;not null;index"`
	UserID    uuid.UUID `json:"user_id" gorm:"type:uuid;not null;index"`
	Scope     string    `json:"scope" gorm:"type:text"`
	ExpiresAt time.Time `json:"expires_at" gorm:"not null;index"`
	CreatedAt time.Time `json:"created_at" gorm:"autoCreateTime"`
}

// RefreshToken represents an OAuth 2.0 refresh token
type RefreshToken struct {
	ID        uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	TenantID  uuid.UUID `json:"tenant_id" gorm:"type:uuid;not null;index"`
	Token     string    `json:"token" gorm:"not null;size:255;uniqueIndex"`
	ClientID  uuid.UUID `json:"client_id" gorm:"type:uuid;not null;index"`
	UserID    uuid.UUID `json:"user_id" gorm:"type:uuid;not null;index"`
	ExpiresAt time.Time `json:"expires_at" gorm:"not null;index"`
	CreatedAt time.Time `json:"created_at" gorm:"autoCreateTime"`
}

// TokenResponse represents the OAuth 2.0 token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// IntrospectionResponse represents the OAuth 2.0 token introspection response
type IntrospectionResponse struct {
	Active   bool   `json:"active"`
	Scope    string `json:"scope,omitempty"`
	ClientID string `json:"client_id,omitempty"`
	UserID   string `json:"user_id,omitempty"`
	Exp      int64  `json:"exp,omitempty"`
	Iat      int64  `json:"iat,omitempty"`
}

// UserInfo represents OpenID Connect UserInfo response
type UserInfo struct {
	Sub           string `json:"sub"`
	Name          string `json:"name,omitempty"`
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
}

// OpenIDConfiguration represents OpenID Provider configuration
type OpenIDConfiguration struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	UserInfoEndpoint                 string   `json:"userinfo_endpoint"`
	JwksURI                          string   `json:"jwks_uri"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                  []string `json:"scopes_supported"`
	ClaimsSupported                  []string `json:"claims_supported"`
}

// JWTClaims represents JWT token claims
type JWTClaims struct {
	Sub      string `json:"sub"`
	Aud      string `json:"aud"`
	Iss      string `json:"iss"`
	Exp      int64  `json:"exp"`
	Iat      int64  `json:"iat"`
	TenantID string `json:"tenant_id"`
	Scope    string `json:"scope,omitempty"`
	ClientID string `json:"client_id,omitempty"`
	UserID   string `json:"user_id,omitempty"`
	Email    string `json:"email,omitempty"`
	Name     string `json:"name,omitempty"`
}

// GetExpirationTime implements jwt.Claims interface
func (c *JWTClaims) GetExpirationTime() (*jwt.NumericDate, error) {
	if c.Exp == 0 {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(c.Exp, 0)), nil
}

// GetIssuedAt implements jwt.Claims interface
func (c *JWTClaims) GetIssuedAt() (*jwt.NumericDate, error) {
	if c.Iat == 0 {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(c.Iat, 0)), nil
}

// GetNotBefore implements jwt.Claims interface
func (c *JWTClaims) GetNotBefore() (*jwt.NumericDate, error) {
	return nil, nil
}

// GetIssuer implements jwt.Claims interface
func (c *JWTClaims) GetIssuer() (string, error) {
	return c.Iss, nil
}

// GetSubject implements jwt.Claims interface
func (c *JWTClaims) GetSubject() (string, error) {
	return c.Sub, nil
}

// GetAudience implements jwt.Claims interface
func (c *JWTClaims) GetAudience() (jwt.ClaimStrings, error) {
	return jwt.ClaimStrings{c.Aud}, nil
}

// CreateClientRequest represents a request to create a new client
type CreateClientRequest struct {
	Name         string   `json:"name" binding:"required"`
	RedirectURIs []string `json:"redirect_uris" binding:"required"`
	GrantTypes   []string `json:"grant_types" binding:"required"`
	Scopes       []string `json:"scopes" binding:"required"`
	IsPublic     bool     `json:"is_public"`
}

// UpdateClientRequest represents a request to update a client
type UpdateClientRequest struct {
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirect_uris"`
	GrantTypes   []string `json:"grant_types"`
	Scopes       []string `json:"scopes"`
	IsPublic     *bool    `json:"is_public"`
}

// CreateUserRequest represents a request to create a new user
type CreateUserRequest struct {
	Username string `json:"username" binding:"required"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
}

// UpdateUserRequest represents a request to update a user
type UpdateUserRequest struct {
	Username string `json:"username"`
	Email    string `json:"email" binding:"omitempty,email"`
	Password string `json:"password" binding:"omitempty,min=8"`
}

// IsExpired checks if the authorization code is expired
func (ac *AuthorizationCode) IsExpired() bool {
	return !time.Now().Before(ac.ExpiresAt)
}

// IsExpired checks if the access token is expired
func (at *AccessToken) IsExpired() bool {
	return !time.Now().Before(at.ExpiresAt)
}

// IsExpired checks if the refresh token is expired
func (rt *RefreshToken) IsExpired() bool {
	return !time.Now().Before(rt.ExpiresAt)
}

// HasRedirectURI checks if the client has the specified redirect URI
func (c *Client) HasRedirectURI(uri string) bool {
	for _, redirectURI := range c.RedirectURIs {
		if redirectURI == uri {
			return true
		}
	}
	return false
}

// HasGrantType checks if the client supports the specified grant type
func (c *Client) HasGrantType(grantType string) bool {
	for _, gt := range c.GrantTypes {
		if gt == grantType {
			return true
		}
	}
	return false
}

// HasScope checks if the client has the specified scope
func (c *Client) HasScope(scope string) bool {
	for _, s := range c.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// CreateTenantRequest represents a request to create a new tenant
type CreateTenantRequest struct {
	Name   string `json:"name" binding:"required"`
	Domain string `json:"domain" binding:"required"`
}

// UpdateTenantRequest represents a request to update a tenant
type UpdateTenantRequest struct {
	Name     string `json:"name"`
	Domain   string `json:"domain"`
	IsActive *bool  `json:"is_active"`
}

// PaginatedResponse represents a paginated API response
type PaginatedResponse struct {
	Items []interface{} `json:"items"`
	Page  PageInfo      `json:"page"`
}

// PageInfo represents pagination information
type PageInfo struct {
	Limit      int    `json:"limit"`
	Offset     int    `json:"offset"`
	TotalCount int64  `json:"total_count"`
	HasMore    bool   `json:"has_more"`
	Cursor     string `json:"cursor,omitempty"`
}

// AuthorizeRequest represents an OAuth authorization request
type AuthorizeRequest struct {
	ResponseType        string `form:"response_type" binding:"required"`
	ClientID            string `form:"client_id" binding:"required"`
	RedirectURI         string `form:"redirect_uri" binding:"required"`
	Scope               string `form:"scope"`
	State               string `form:"state"`
	CodeChallenge       string `form:"code_challenge"`
	CodeChallengeMethod string `form:"code_challenge_method"`
	Nonce               string `form:"nonce"`
}

// TokenRequest represents an OAuth token request
type TokenRequest struct {
	GrantType    string `form:"grant_type" binding:"required"`
	Code         string `form:"code"`
	RedirectURI  string `form:"redirect_uri"`
	ClientID     string `form:"client_id"`
	ClientSecret string `form:"client_secret"`
	CodeVerifier string `form:"code_verifier"`
	RefreshToken string `form:"refresh_token"`
	Scope        string `form:"scope"`
}

// IntrospectRequest represents a token introspection request
type IntrospectRequest struct {
	Token         string `form:"token" binding:"required"`
	TokenTypeHint string `form:"token_type_hint"`
}

// RevokeRequest represents a token revocation request
type RevokeRequest struct {
	Token         string `form:"token" binding:"required"`
	TokenTypeHint string `form:"token_type_hint"`
}

// LoginRequest represents a user login request
type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// ChangePasswordRequest represents a password change request
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=8"`
}

// Validation helper methods
func (r *AuthorizeRequest) Validate() error {
	if r.ResponseType != "code" {
		return fmt.Errorf("unsupported response_type: %s", r.ResponseType)
	}
	return nil
}

func (r *TokenRequest) Validate() error {
	switch r.GrantType {
	case "authorization_code":
		if r.Code == "" || r.RedirectURI == "" {
			return fmt.Errorf("code and redirect_uri are required for authorization_code grant")
		}
	case "refresh_token":
		if r.RefreshToken == "" {
			return fmt.Errorf("refresh_token is required for refresh_token grant")
		}
	case "client_credentials":
		// Client credentials are validated separately
	default:
		return fmt.Errorf("unsupported grant_type: %s", r.GrantType)
	}
	return nil
}

// Helper functions for pagination
func NewPaginatedResponse(items []interface{}, limit, offset int, totalCount int64) *PaginatedResponse {
	hasMore := int64(offset+limit) < totalCount

	return &PaginatedResponse{
		Items: items,
		Page: PageInfo{
			Limit:      limit,
			Offset:     offset,
			TotalCount: totalCount,
			HasMore:    hasMore,
		},
	}
}

// Helper functions for converting slices to interface slices
func UsersToInterface(users []*User) []interface{} {
	items := make([]interface{}, len(users))
	for i, user := range users {
		items[i] = user
	}
	return items
}

func ClientsToInterface(clients []*Client) []interface{} {
	items := make([]interface{}, len(clients))
	for i, client := range clients {
		items[i] = client
	}
	return items
}

func TenantsToInterface(tenants []*Tenant) []interface{} {
	items := make([]interface{}, len(tenants))
	for i, tenant := range tenants {
		items[i] = tenant
	}
	return items
}
