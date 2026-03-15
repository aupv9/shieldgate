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
	// RBAC errors
	ErrRoleNotFound       = errors.New("role not found")
	ErrPermissionNotFound = errors.New("permission not found")
	ErrPermissionDenied   = errors.New("permission denied")
	// RBAC business-rule errors
	ErrDuplicateResource     = errors.New("resource already exists")
	ErrBusinessRuleViolation = errors.New("business rule violation")
	// User management errors
	ErrUserLocked              = errors.New("user account is locked")
	ErrUserSuspended           = errors.New("user account is suspended")
	ErrUserPending             = errors.New("user account is pending verification")
	ErrEmailNotVerified        = errors.New("email not verified")
	ErrInvalidVerificationCode = errors.New("invalid verification code")
	ErrVerificationExpired     = errors.New("verification code expired")
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
	// RBAC error codes
	ErrorCodeRoleNotFound       = "ROLE_NOT_FOUND"
	ErrorCodePermissionNotFound = "PERMISSION_NOT_FOUND"
	ErrorCodePermissionDenied   = "PERMISSION_DENIED"
	// User management error codes
	ErrorCodeUserLocked              = "USER_LOCKED"
	ErrorCodeUserSuspended           = "USER_SUSPENDED"
	ErrorCodeUserPending             = "USER_PENDING"
	ErrorCodeEmailNotVerified        = "EMAIL_NOT_VERIFIED"
	ErrorCodeInvalidVerificationCode = "INVALID_VERIFICATION_CODE"
	ErrorCodeVerificationExpired     = "VERIFICATION_EXPIRED"
)

// User status constants
type UserStatus string

const (
	UserStatusActive    UserStatus = "active"
	UserStatusSuspended UserStatus = "suspended"
	UserStatusPending   UserStatus = "pending"
	UserStatusLocked    UserStatus = "locked"
)

// Audit action constants
type AuditAction string

const (
	AuditActionUserLogin         AuditAction = "user.login"
	AuditActionUserLoginFailed   AuditAction = "user.login.failed"
	AuditActionUserLogout        AuditAction = "user.logout"
	AuditActionUserCreated       AuditAction = "user.created"
	AuditActionUserUpdated       AuditAction = "user.updated"
	AuditActionUserDeleted       AuditAction = "user.deleted"
	AuditActionUserLocked        AuditAction = "user.locked"
	AuditActionUserUnlocked      AuditAction = "user.unlocked"
	AuditActionUserSuspended     AuditAction = "user.suspended"
	AuditActionPasswordChanged   AuditAction = "user.password.changed"
	AuditActionEmailVerified     AuditAction = "user.email.verified"
	AuditActionTokenGenerated    AuditAction = "token.generated"
	AuditActionTokenRevoked      AuditAction = "token.revoked"
	AuditActionClientCreated     AuditAction = "client.created"
	AuditActionClientUpdated     AuditAction = "client.updated"
	AuditActionClientDeleted     AuditAction = "client.deleted"
	AuditActionRoleCreated       AuditAction = "role.created"
	AuditActionRoleUpdated       AuditAction = "role.updated"
	AuditActionRoleDeleted       AuditAction = "role.deleted"
	AuditActionRoleAssigned      AuditAction = "role.assigned"
	AuditActionRoleRevoked       AuditAction = "role.revoked"
	AuditActionPermissionGranted AuditAction = "permission.granted"
	AuditActionPermissionRevoked AuditAction = "permission.revoked"
)

// Email template types
type EmailTemplate string

const (
	EmailTemplateWelcome           EmailTemplate = "welcome"
	EmailTemplateEmailVerification EmailTemplate = "email_verification"
	EmailTemplatePasswordReset     EmailTemplate = "password_reset"
	EmailTemplatePasswordChanged   EmailTemplate = "password_changed"
	EmailTemplateAccountLocked     EmailTemplate = "account_locked"
	EmailTemplateAccountSuspended  EmailTemplate = "account_suspended"
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
	ID                         uuid.UUID      `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	TenantID                   uuid.UUID      `json:"tenant_id" gorm:"type:uuid;not null;index:idx_users_tenant_id"`
	Username                   string         `json:"username" gorm:"not null;size:255;index:idx_users_tenant_username,unique"`
	Email                      string         `json:"email" gorm:"not null;size:255;index:idx_users_tenant_email,unique"`
	PasswordHash               string         `json:"-" gorm:"not null;size:255"`
	Status                     UserStatus     `json:"status" gorm:"not null;default:'pending';index"`
	EmailVerified              bool           `json:"email_verified" gorm:"not null;default:false"`
	EmailVerificationCode      string         `json:"-" gorm:"size:255"`
	EmailVerificationExpiresAt *time.Time     `json:"-"`
	PhoneNumber                string         `json:"phone_number" gorm:"size:50"`
	PhoneVerified              bool           `json:"phone_verified" gorm:"not null;default:false"`
	FirstName                  string         `json:"first_name" gorm:"size:255"`
	LastName                   string         `json:"last_name" gorm:"size:255"`
	Avatar                     string         `json:"avatar" gorm:"size:500"`
	Locale                     string         `json:"locale" gorm:"size:10;default:'en'"`
	Timezone                   string         `json:"timezone" gorm:"size:50;default:'UTC'"`
	LastLoginAt                *time.Time     `json:"last_login_at"`
	LastLoginIP                string         `json:"last_login_ip" gorm:"size:45"`
	FailedLoginAttempts        int            `json:"failed_login_attempts" gorm:"not null;default:0"`
	LockedAt                   *time.Time     `json:"locked_at"`
	LockedUntil                *time.Time     `json:"locked_until"`
	PasswordResetToken         string         `json:"-" gorm:"size:255"`
	PasswordResetExpiresAt     *time.Time     `json:"-"`
	Metadata                   JSON           `json:"metadata" gorm:"type:jsonb;default:'{}'"`
	CreatedAt                  time.Time      `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt                  time.Time      `json:"updated_at" gorm:"autoUpdateTime"`
	DeletedAt                  gorm.DeletedAt `json:"-" gorm:"index"`

	// Relationships
	Roles []UserRole `json:"roles,omitempty" gorm:"foreignKey:UserID"`
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

// JSON represents a JSON field type
type JSON map[string]interface{}

// Value implements the driver.Valuer interface
func (j JSON) Value() (driver.Value, error) {
	if j == nil {
		return nil, nil
	}
	return json.Marshal(j)
}

// Scan implements the sql.Scanner interface
func (j *JSON) Scan(value interface{}) error {
	if value == nil {
		*j = nil
		return nil
	}

	switch v := value.(type) {
	case []byte:
		return json.Unmarshal(v, j)
	case string:
		return json.Unmarshal([]byte(v), j)
	default:
		return errors.New("cannot scan into JSON")
	}
}

// RBAC Models

// Role represents a role in the RBAC system
type Role struct {
	ID          uuid.UUID      `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	TenantID    uuid.UUID      `json:"tenant_id" gorm:"type:uuid;not null;index:idx_roles_tenant_id"`
	Name        string         `json:"name" gorm:"not null;size:255;index:idx_roles_tenant_name,unique"`
	DisplayName string         `json:"display_name" gorm:"not null;size:255"`
	Description string         `json:"description" gorm:"type:text"`
	IsSystem    bool           `json:"is_system" gorm:"not null;default:false"`
	IsActive    bool           `json:"is_active" gorm:"not null;default:true"`
	CreatedAt   time.Time      `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt   time.Time      `json:"updated_at" gorm:"autoUpdateTime"`
	DeletedAt   gorm.DeletedAt `json:"-" gorm:"index"`

	// Relationships
	Permissions []RolePermission `json:"permissions,omitempty" gorm:"foreignKey:RoleID"`
	Users       []UserRole       `json:"users,omitempty" gorm:"foreignKey:RoleID"`
}

// Permission represents a permission in the RBAC system
type Permission struct {
	ID          uuid.UUID      `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	Name        string         `json:"name" gorm:"not null;size:255;uniqueIndex"`
	DisplayName string         `json:"display_name" gorm:"not null;size:255"`
	Description string         `json:"description" gorm:"type:text"`
	Resource    string         `json:"resource" gorm:"not null;size:255;index"`
	Action      string         `json:"action" gorm:"not null;size:255;index"`
	IsSystem    bool           `json:"is_system" gorm:"not null;default:false"`
	CreatedAt   time.Time      `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt   time.Time      `json:"updated_at" gorm:"autoUpdateTime"`
	DeletedAt   gorm.DeletedAt `json:"-" gorm:"index"`

	// Relationships
	Roles []RolePermission `json:"roles,omitempty" gorm:"foreignKey:PermissionID"`
}

// UserRole represents the many-to-many relationship between users and roles
type UserRole struct {
	ID        uuid.UUID  `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	TenantID  uuid.UUID  `json:"tenant_id" gorm:"type:uuid;not null;index"`
	UserID    uuid.UUID  `json:"user_id" gorm:"type:uuid;not null;index:idx_user_roles_user_id"`
	RoleID    uuid.UUID  `json:"role_id" gorm:"type:uuid;not null;index:idx_user_roles_role_id"`
	GrantedBy uuid.UUID  `json:"granted_by" gorm:"type:uuid;not null"`
	GrantedAt time.Time  `json:"granted_at" gorm:"autoCreateTime"`
	ExpiresAt *time.Time `json:"expires_at"`

	// Relationships
	User User `json:"user,omitempty" gorm:"foreignKey:UserID"`
	Role Role `json:"role,omitempty" gorm:"foreignKey:RoleID"`
}

// RolePermission represents the many-to-many relationship between roles and permissions
type RolePermission struct {
	ID           uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	RoleID       uuid.UUID `json:"role_id" gorm:"type:uuid;not null;index:idx_role_permissions_role_id"`
	PermissionID uuid.UUID `json:"permission_id" gorm:"type:uuid;not null;index:idx_role_permissions_permission_id"`
	GrantedBy    uuid.UUID `json:"granted_by" gorm:"type:uuid;not null"`
	GrantedAt    time.Time `json:"granted_at" gorm:"autoCreateTime"`

	// Relationships
	Role       Role       `json:"role,omitempty" gorm:"foreignKey:RoleID"`
	Permission Permission `json:"permission,omitempty" gorm:"foreignKey:PermissionID"`
}

// Audit Logging Models

// AuditLog represents an audit log entry
type AuditLog struct {
	ID           uuid.UUID   `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	TenantID     uuid.UUID   `json:"tenant_id" gorm:"type:uuid;not null;index:idx_audit_logs_tenant_id"`
	UserID       *uuid.UUID  `json:"user_id" gorm:"type:uuid;index:idx_audit_logs_user_id"`
	ClientID     *uuid.UUID  `json:"client_id" gorm:"type:uuid;index:idx_audit_logs_client_id"`
	Action       AuditAction `json:"action" gorm:"not null;size:255;index:idx_audit_logs_action"`
	Resource     string      `json:"resource" gorm:"not null;size:255;index:idx_audit_logs_resource"`
	ResourceID   *uuid.UUID  `json:"resource_id" gorm:"type:uuid;index:idx_audit_logs_resource_id"`
	IPAddress    string      `json:"ip_address" gorm:"size:45;index:idx_audit_logs_ip"`
	UserAgent    string      `json:"user_agent" gorm:"type:text"`
	RequestID    string      `json:"request_id" gorm:"size:255;index:idx_audit_logs_request_id"`
	Success      bool        `json:"success" gorm:"not null;index:idx_audit_logs_success"`
	ErrorCode    string      `json:"error_code" gorm:"size:255"`
	ErrorMessage string      `json:"error_message" gorm:"type:text"`
	Metadata     JSON        `json:"metadata" gorm:"type:jsonb;default:'{}'"`
	CreatedAt    time.Time   `json:"created_at" gorm:"autoCreateTime;index:idx_audit_logs_created_at"`

	// Relationships
	User   *User   `json:"user,omitempty" gorm:"foreignKey:UserID"`
	Client *Client `json:"client,omitempty" gorm:"foreignKey:ClientID"`
}

// Email System Models

// EmailTemplate represents an email template
type EmailTemplate struct {
	ID        uuid.UUID      `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	TenantID  uuid.UUID      `json:"tenant_id" gorm:"type:uuid;not null;index:idx_email_templates_tenant_id"`
	Name      string         `json:"name" gorm:"not null;size:255;index:idx_email_templates_tenant_name,unique"`
	Subject   string         `json:"subject" gorm:"not null;size:500"`
	BodyHTML  string         `json:"body_html" gorm:"type:text"`
	BodyText  string         `json:"body_text" gorm:"type:text"`
	Variables StringArray    `json:"variables" gorm:"type:jsonb;default:'[]'"`
	IsActive  bool           `json:"is_active" gorm:"not null;default:true"`
	CreatedAt time.Time      `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt time.Time      `json:"updated_at" gorm:"autoUpdateTime"`
	DeletedAt gorm.DeletedAt `json:"-" gorm:"index"`
}

// EmailQueue represents an email in the sending queue
type EmailQueue struct {
	ID          uuid.UUID  `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	TenantID    uuid.UUID  `json:"tenant_id" gorm:"type:uuid;not null;index:idx_email_queue_tenant_id"`
	UserID      *uuid.UUID `json:"user_id" gorm:"type:uuid;index:idx_email_queue_user_id"`
	ToEmail     string     `json:"to_email" gorm:"not null;size:255;index:idx_email_queue_to_email"`
	ToName      string     `json:"to_name" gorm:"size:255"`
	FromEmail   string     `json:"from_email" gorm:"not null;size:255"`
	FromName    string     `json:"from_name" gorm:"size:255"`
	Subject     string     `json:"subject" gorm:"not null;size:500"`
	BodyHTML    string     `json:"body_html" gorm:"type:text"`
	BodyText    string     `json:"body_text" gorm:"type:text"`
	Status      string     `json:"status" gorm:"not null;size:50;default:'pending';index:idx_email_queue_status"`
	Priority    int        `json:"priority" gorm:"not null;default:5;index:idx_email_queue_priority"`
	Attempts    int        `json:"attempts" gorm:"not null;default:0"`
	MaxAttempts int        `json:"max_attempts" gorm:"not null;default:3"`
	LastError   string     `json:"last_error" gorm:"type:text"`
	ScheduledAt time.Time  `json:"scheduled_at" gorm:"not null;index:idx_email_queue_scheduled_at"`
	SentAt      *time.Time `json:"sent_at"`
	CreatedAt   time.Time  `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt   time.Time  `json:"updated_at" gorm:"autoUpdateTime"`

	// Relationships
	User *User `json:"user,omitempty" gorm:"foreignKey:UserID"`
}

// EmailVerification represents an email verification record
type EmailVerification struct {
	ID         uuid.UUID  `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	TenantID   uuid.UUID  `json:"tenant_id" gorm:"type:uuid;not null;index"`
	UserID     uuid.UUID  `json:"user_id" gorm:"type:uuid;not null;index:idx_email_verifications_user_id"`
	Email      string     `json:"email" gorm:"not null;size:255;index"`
	Code       string     `json:"code" gorm:"not null;size:255;uniqueIndex"`
	ExpiresAt  time.Time  `json:"expires_at" gorm:"not null;index"`
	VerifiedAt *time.Time `json:"verified_at"`
	CreatedAt  time.Time  `json:"created_at" gorm:"autoCreateTime"`

	// Relationships
	User User `json:"user,omitempty" gorm:"foreignKey:UserID"`
}

// PasswordReset represents a password reset request
type PasswordReset struct {
	ID        uuid.UUID  `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	TenantID  uuid.UUID  `json:"tenant_id" gorm:"type:uuid;not null;index"`
	UserID    uuid.UUID  `json:"user_id" gorm:"type:uuid;not null;index:idx_password_resets_user_id"`
	Token     string     `json:"token" gorm:"not null;size:255;uniqueIndex"`
	ExpiresAt time.Time  `json:"expires_at" gorm:"not null;index"`
	UsedAt    *time.Time `json:"used_at"`
	CreatedAt time.Time  `json:"created_at" gorm:"autoCreateTime"`

	// Relationships
	User User `json:"user,omitempty" gorm:"foreignKey:UserID"`
}

// Request/Response Models for new features

// CreateRoleRequest represents a request to create a new role
type CreateRoleRequest struct {
	Name        string   `json:"name" binding:"required"`
	DisplayName string   `json:"display_name" binding:"required"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
}

// UpdateRoleRequest represents a request to update a role
type UpdateRoleRequest struct {
	DisplayName string   `json:"display_name"`
	Description string   `json:"description"`
	IsActive    *bool    `json:"is_active"`
	Permissions []string `json:"permissions"`
}

// AssignRoleRequest represents a request to assign a role to a user
type AssignRoleRequest struct {
	UserID    uuid.UUID  `json:"user_id" binding:"required"`
	RoleID    uuid.UUID  `json:"role_id" binding:"required"`
	ExpiresAt *time.Time `json:"expires_at"`
}

// CreatePermissionRequest represents a request to create a new permission
type CreatePermissionRequest struct {
	Name        string `json:"name" binding:"required"`
	DisplayName string `json:"display_name" binding:"required"`
	Description string `json:"description"`
	Resource    string `json:"resource" binding:"required"`
	Action      string `json:"action" binding:"required"`
}

// UpdatePermissionRequest represents a request to update a permission
type UpdatePermissionRequest struct {
	DisplayName string `json:"display_name"`
	Description string `json:"description"`
	Resource    string `json:"resource"`
	Action      string `json:"action"`
}

// SendEmailRequest represents a request to send an email
type SendEmailRequest struct {
	ToEmail   string            `json:"to_email" binding:"required,email"`
	ToName    string            `json:"to_name"`
	Template  string            `json:"template" binding:"required"`
	Variables map[string]string `json:"variables"`
	Priority  int               `json:"priority"`
}

// VerifyEmailRequest represents a request to verify an email
type VerifyEmailRequest struct {
	Code string `json:"code" binding:"required"`
}

// RequestPasswordResetRequest represents a request to reset password
type RequestPasswordResetRequest struct {
	Email string `json:"email" binding:"required,email"`
}

// ResetPasswordRequest represents a request to reset password with token
type ResetPasswordRequest struct {
	Token       string `json:"token" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=8"`
}

// AuditLogQuery represents query parameters for audit log search
type AuditLogQuery struct {
	TenantID   uuid.UUID    `json:"tenant_id"`
	UserID     *uuid.UUID   `json:"user_id"`
	ClientID   *uuid.UUID   `json:"client_id"`
	Action     *AuditAction `json:"action"`
	Resource   string       `json:"resource"`
	ResourceID *uuid.UUID   `json:"resource_id"`
	IPAddress  string       `json:"ip_address"`
	Success    *bool        `json:"success"`
	StartDate  *time.Time   `json:"start_date"`
	EndDate    *time.Time   `json:"end_date"`
	Limit      int          `json:"limit"`
	Offset     int          `json:"offset"`
}

// Helper methods for new models

// IsExpired checks if the email verification is expired
func (ev *EmailVerification) IsExpired() bool {
	return time.Now().After(ev.ExpiresAt)
}

// IsExpired checks if the password reset is expired
func (pr *PasswordReset) IsExpired() bool {
	return time.Now().After(pr.ExpiresAt)
}

// IsUsed checks if the password reset has been used
func (pr *PasswordReset) IsUsed() bool {
	return pr.UsedAt != nil
}

// IsLocked checks if the user account is locked
func (u *User) IsLocked() bool {
	return u.Status == UserStatusLocked || (u.LockedUntil != nil && time.Now().Before(*u.LockedUntil))
}

// IsSuspended checks if the user account is suspended
func (u *User) IsSuspended() bool {
	return u.Status == UserStatusSuspended
}

// IsPending checks if the user account is pending verification
func (u *User) IsPending() bool {
	return u.Status == UserStatusPending
}

// IsActive checks if the user account is active
func (u *User) IsActive() bool {
	return u.Status == UserStatusActive && !u.IsLocked() && !u.IsSuspended()
}

// GetFullName returns the user's full name
func (u *User) GetFullName() string {
	if u.FirstName != "" && u.LastName != "" {
		return u.FirstName + " " + u.LastName
	}
	if u.FirstName != "" {
		return u.FirstName
	}
	if u.LastName != "" {
		return u.LastName
	}
	return u.Username
}

// HasPermission checks if a role has a specific permission
func (r *Role) HasPermission(permissionName string) bool {
	for _, rp := range r.Permissions {
		if rp.Permission.Name == permissionName {
			return true
		}
	}
	return false
}

// IsExpired checks if a user role assignment is expired
func (ur *UserRole) IsExpired() bool {
	return ur.ExpiresAt != nil && time.Now().After(*ur.ExpiresAt)
}
