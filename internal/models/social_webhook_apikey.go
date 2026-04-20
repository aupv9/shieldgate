package models

import (
	"errors"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Phase 7 errors
var (
	ErrAPIKeyNotFound              = errors.New("api key not found")
	ErrAPIKeyRevoked               = errors.New("api key has been revoked")
	ErrAPIKeyExpired               = errors.New("api key has expired")
	ErrWebhookNotFound             = errors.New("webhook not found")
	ErrSocialAccountExists         = errors.New("social account already linked")
	ErrSocialAccountNotFound       = errors.New("social account not found")
	ErrSocialProviderNotSupported  = errors.New("social provider not supported")
	ErrSocialProviderNotConfigured = errors.New("social provider not configured for this tenant")
)

// SocialProvider holds per-tenant OAuth2 provider credentials
type SocialProvider struct {
	ID           uuid.UUID      `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	TenantID     uuid.UUID      `json:"tenant_id" gorm:"type:uuid;not null;uniqueIndex:idx_social_providers_tenant_provider"`
	Provider     string         `json:"provider" gorm:"not null;size:50;uniqueIndex:idx_social_providers_tenant_provider"`
	ClientID     string         `json:"client_id" gorm:"not null;size:255"`
	ClientSecret string         `json:"-" gorm:"not null;size:255"`
	Scopes       StringArray    `json:"scopes" gorm:"type:jsonb;not null;default:'[]'"`
	IsActive     bool           `json:"is_active" gorm:"not null;default:true"`
	CreatedAt    time.Time      `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt    time.Time      `json:"updated_at" gorm:"autoUpdateTime"`
	DeletedAt    gorm.DeletedAt `json:"-" gorm:"index"`
}

// SocialAccount links a user account to a social provider identity
type SocialAccount struct {
	ID             uuid.UUID  `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	TenantID       uuid.UUID  `json:"tenant_id" gorm:"type:uuid;not null;index"`
	UserID         uuid.UUID  `json:"user_id" gorm:"type:uuid;not null;index:idx_social_accounts_user"`
	Provider       string     `json:"provider" gorm:"not null;size:50;uniqueIndex:idx_social_accounts_provider_external"`
	ExternalID     string     `json:"external_id" gorm:"not null;size:255;uniqueIndex:idx_social_accounts_provider_external"`
	Email          string     `json:"email" gorm:"size:255"`
	Name           string     `json:"name" gorm:"size:255"`
	Avatar         string     `json:"avatar" gorm:"size:500"`
	AccessToken    string     `json:"-" gorm:"type:text"`
	RefreshToken   string     `json:"-" gorm:"type:text"`
	TokenExpiresAt *time.Time `json:"token_expires_at"`
	CreatedAt      time.Time  `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt      time.Time  `json:"updated_at" gorm:"autoUpdateTime"`
}

// WebhookEndpoint is a configured endpoint receiving event notifications
type WebhookEndpoint struct {
	ID          uuid.UUID      `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	TenantID    uuid.UUID      `json:"tenant_id" gorm:"type:uuid;not null;index:idx_webhooks_tenant_id"`
	URL         string         `json:"url" gorm:"not null;size:500"`
	Secret      string         `json:"-" gorm:"not null;size:255"`
	Events      StringArray    `json:"events" gorm:"type:jsonb;not null;default:'[]'"`
	IsActive    bool           `json:"is_active" gorm:"not null;default:true"`
	Description string         `json:"description" gorm:"size:500"`
	CreatedAt   time.Time      `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt   time.Time      `json:"updated_at" gorm:"autoUpdateTime"`
	DeletedAt   gorm.DeletedAt `json:"-" gorm:"index"`
}

// WebhookDelivery records each event delivery attempt
type WebhookDelivery struct {
	ID           uuid.UUID  `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	WebhookID    uuid.UUID  `json:"webhook_id" gorm:"type:uuid;not null;index:idx_webhook_deliveries_webhook_id"`
	TenantID     uuid.UUID  `json:"tenant_id" gorm:"type:uuid;not null;index"`
	Event        string     `json:"event" gorm:"not null;size:255;index"`
	Payload      string     `json:"payload" gorm:"type:text"`
	StatusCode   int        `json:"status_code"`
	ResponseBody string     `json:"response_body" gorm:"type:text"`
	Attempt      int        `json:"attempt" gorm:"not null;default:1"`
	Success      bool       `json:"success" gorm:"not null;default:false;index"`
	ErrorMessage string     `json:"error_message" gorm:"type:text"`
	DeliveredAt  *time.Time `json:"delivered_at"`
	CreatedAt    time.Time  `json:"created_at" gorm:"autoCreateTime;index"`
}

// APIKey represents a long-lived programmatic access key
type APIKey struct {
	ID         uuid.UUID      `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	TenantID   uuid.UUID      `json:"tenant_id" gorm:"type:uuid;not null;index:idx_api_keys_tenant_id"`
	UserID     *uuid.UUID     `json:"user_id" gorm:"type:uuid;index:idx_api_keys_user_id"`
	Name       string         `json:"name" gorm:"not null;size:255"`
	KeyHash    string         `json:"-" gorm:"not null;size:255;uniqueIndex"`
	LastFour   string         `json:"last_four" gorm:"not null;size:4"`
	Prefix     string         `json:"prefix" gorm:"not null;size:10"`
	Scopes     StringArray    `json:"scopes" gorm:"type:jsonb;not null;default:'[]'"`
	ExpiresAt  *time.Time     `json:"expires_at"`
	LastUsedAt *time.Time     `json:"last_used_at"`
	RevokedAt  *time.Time     `json:"revoked_at"`
	CreatedAt  time.Time      `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt  time.Time      `json:"updated_at" gorm:"autoUpdateTime"`
	DeletedAt  gorm.DeletedAt `json:"-" gorm:"index"`
}

func (k *APIKey) IsExpired() bool { return k.ExpiresAt != nil && time.Now().After(*k.ExpiresAt) }
func (k *APIKey) IsRevoked() bool { return k.RevokedAt != nil }
func (k *APIKey) IsActive() bool  { return !k.IsRevoked() && !k.IsExpired() }

// ─── Request / Response DTOs ──────────────────────────────────────────────────

// CreateWebhookRequest is the payload for POST /v1/webhooks
type CreateWebhookRequest struct {
	URL         string   `json:"url" binding:"required,url"`
	Events      []string `json:"events" binding:"required,min=1"`
	Description string   `json:"description"`
	Secret      string   `json:"secret"`
}

// UpdateWebhookRequest is the payload for PUT /v1/webhooks/:id
type UpdateWebhookRequest struct {
	URL         string   `json:"url" binding:"omitempty,url"`
	Events      []string `json:"events"`
	Description string   `json:"description"`
	IsActive    *bool    `json:"is_active"`
}

// CreateAPIKeyRequest is the payload for POST /v1/apikeys
type CreateAPIKeyRequest struct {
	Name      string     `json:"name" binding:"required"`
	Scopes    []string   `json:"scopes"`
	ExpiresAt *time.Time `json:"expires_at"`
}

// APIKeyCreateResponse is returned once on key creation; Key is not stored
type APIKeyCreateResponse struct {
	ID        uuid.UUID   `json:"id"`
	TenantID  uuid.UUID   `json:"tenant_id"`
	UserID    *uuid.UUID  `json:"user_id,omitempty"`
	Name      string      `json:"name"`
	Key       string      `json:"key"`
	LastFour  string      `json:"last_four"`
	Prefix    string      `json:"prefix"`
	Scopes    StringArray `json:"scopes"`
	ExpiresAt *time.Time  `json:"expires_at"`
	CreatedAt time.Time   `json:"created_at"`
}
