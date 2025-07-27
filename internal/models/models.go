package models

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"gorm.io/gorm"
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

// User represents a user in the system
type User struct {
	ID           uuid.UUID      `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	Username     string         `json:"username" gorm:"uniqueIndex;not null;size:255"`
	Email        string         `json:"email" gorm:"uniqueIndex;not null;size:255"`
	PasswordHash string         `json:"-" gorm:"not null;size:255"`
	CreatedAt    time.Time      `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt    time.Time      `json:"updated_at" gorm:"autoUpdateTime"`
	DeletedAt    gorm.DeletedAt `json:"-" gorm:"index"`
}

// Client represents an OAuth 2.0 client
type Client struct {
	ID           uuid.UUID      `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	ClientID     string         `json:"client_id" gorm:"uniqueIndex;not null;size:255"`
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
	ID                    uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	Code                  string    `json:"code" gorm:"uniqueIndex;not null;size:255"`
	ClientID              uuid.UUID `json:"client_id" gorm:"type:uuid;not null;index"`
	UserID                uuid.UUID `json:"user_id" gorm:"type:uuid;not null;index"`
	RedirectURI           string    `json:"redirect_uri" gorm:"not null;size:255"`
	Scope                 string    `json:"scope" gorm:"type:text"`
	CodeChallenge         string    `json:"code_challenge" gorm:"size:255"`
	CodeChallengeMethod   string    `json:"code_challenge_method" gorm:"size:50"`
	ExpiresAt             time.Time `json:"expires_at" gorm:"not null;index"`
	CreatedAt             time.Time `json:"created_at" gorm:"autoCreateTime"`
	
	// Foreign key relationships
	Client Client `json:"-" gorm:"foreignKey:ClientID;constraint:OnDelete:CASCADE"`
	User   User   `json:"-" gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`
}

// AccessToken represents an OAuth 2.0 access token
type AccessToken struct {
	ID        uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	Token     string    `json:"token" gorm:"uniqueIndex;not null;size:255"`
	ClientID  uuid.UUID `json:"client_id" gorm:"type:uuid;not null;index"`
	UserID    uuid.UUID `json:"user_id" gorm:"type:uuid;not null;index"`
	Scope     string    `json:"scope" gorm:"type:text"`
	ExpiresAt time.Time `json:"expires_at" gorm:"not null;index"`
	CreatedAt time.Time `json:"created_at" gorm:"autoCreateTime"`
	
	// Foreign key relationships
	Client Client `json:"-" gorm:"foreignKey:ClientID;constraint:OnDelete:CASCADE"`
	User   User   `json:"-" gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`
}

// RefreshToken represents an OAuth 2.0 refresh token
type RefreshToken struct {
	ID        uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	Token     string    `json:"token" gorm:"uniqueIndex;not null;size:255"`
	ClientID  uuid.UUID `json:"client_id" gorm:"type:uuid;not null;index"`
	UserID    uuid.UUID `json:"user_id" gorm:"type:uuid;not null;index"`
	ExpiresAt time.Time `json:"expires_at" gorm:"not null;index"`
	CreatedAt time.Time `json:"created_at" gorm:"autoCreateTime"`
	
	// Foreign key relationships
	Client Client `json:"-" gorm:"foreignKey:ClientID;constraint:OnDelete:CASCADE"`
	User   User   `json:"-" gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`
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
	Active   bool      `json:"active"`
	Scope    string    `json:"scope,omitempty"`
	ClientID string    `json:"client_id,omitempty"`
	UserID   string    `json:"user_id,omitempty"`
	Exp      int64     `json:"exp,omitempty"`
	Iat      int64     `json:"iat,omitempty"`
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
	Sub       string `json:"sub"`
	Aud       string `json:"aud"`
	Iss       string `json:"iss"`
	Exp       int64  `json:"exp"`
	Iat       int64  `json:"iat"`
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	UserID    string `json:"user_id,omitempty"`
	Email     string `json:"email,omitempty"`
	Name      string `json:"name,omitempty"`
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