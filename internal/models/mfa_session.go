package models

import (
	"errors"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// ─── MFA errors ────────────────────────────────────────────────────────────────

var (
	ErrMFAAlreadyEnabled   = errors.New("MFA is already enabled")
	ErrMFANotEnabled       = errors.New("MFA is not enabled")
	ErrMFANotSetup         = errors.New("MFA has not been set up")
	ErrMFAInvalidCode      = errors.New("invalid MFA code")
	ErrMFABackupCodeUsed   = errors.New("backup code has already been used")
	ErrMFABackupCodeInvalid = errors.New("invalid backup code")
	ErrSessionNotFound     = errors.New("session not found")
	ErrSessionRevoked      = errors.New("session has been revoked")
	ErrSessionExpired      = errors.New("session has expired")
	ErrTooManyLoginAttempts = errors.New("too many login attempts")
)

// ─── MFASecret ─────────────────────────────────────────────────────────────────

// MFASecret holds the per-user TOTP secret.
type MFASecret struct {
	ID        uuid.UUID `json:"id"       gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	TenantID  uuid.UUID `json:"tenant_id" gorm:"type:uuid;not null;index:idx_mfa_secrets_tenant"`
	UserID    uuid.UUID `json:"user_id"   gorm:"type:uuid;not null;uniqueIndex:idx_mfa_secrets_user_tenant"`
	Secret    string    `json:"-"        gorm:"not null;size:255"`
	Algorithm string    `json:"algorithm" gorm:"not null;size:20;default:'SHA1'"`
	Digits    int       `json:"digits"    gorm:"not null;default:6"`
	Period    int       `json:"period"    gorm:"not null;default:30"`
	Enabled   bool      `json:"enabled"   gorm:"not null;default:false"`
	CreatedAt time.Time `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt time.Time `json:"updated_at" gorm:"autoUpdateTime"`
}

// ─── MFABackupCode ─────────────────────────────────────────────────────────────

// MFABackupCode is a single-use recovery code for MFA.
type MFABackupCode struct {
	ID        uuid.UUID  `json:"id"        gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	TenantID  uuid.UUID  `json:"tenant_id" gorm:"type:uuid;not null;index"`
	UserID    uuid.UUID  `json:"user_id"   gorm:"type:uuid;not null;index:idx_mfa_backup_codes_user"`
	CodeHash  string     `json:"-"         gorm:"not null;size:255;uniqueIndex"`
	UsedAt    *time.Time `json:"used_at"`
	CreatedAt time.Time  `json:"created_at" gorm:"autoCreateTime"`
}

// IsUsed returns true if this backup code has been consumed.
func (c *MFABackupCode) IsUsed() bool { return c.UsedAt != nil }

// ─── Session ───────────────────────────────────────────────────────────────────

// Session tracks an authenticated user session (one per token).
type Session struct {
	ID           uuid.UUID      `json:"id"             gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	TenantID     uuid.UUID      `json:"tenant_id"      gorm:"type:uuid;not null;index"`
	UserID       uuid.UUID      `json:"user_id"        gorm:"type:uuid;not null;index:idx_sessions_user"`
	TokenID      string         `json:"token_id"       gorm:"not null;size:255;uniqueIndex"`
	IPAddress    string         `json:"ip_address"     gorm:"size:45;index"`
	UserAgent    string         `json:"user_agent"     gorm:"type:text"`
	DeviceName   string         `json:"device_name"    gorm:"size:255"`
	LastActiveAt time.Time      `json:"last_active_at" gorm:"index"`
	ExpiresAt    time.Time      `json:"expires_at"     gorm:"not null;index"`
	RevokedAt    *time.Time     `json:"revoked_at"`
	CreatedAt    time.Time      `json:"created_at"     gorm:"autoCreateTime"`
	DeletedAt    gorm.DeletedAt `json:"-"              gorm:"index"`
}

// IsRevoked returns true if the session was explicitly revoked.
func (s *Session) IsRevoked() bool { return s.RevokedAt != nil }

// IsExpired returns true if the session's expiry time has passed.
func (s *Session) IsExpired() bool { return time.Now().After(s.ExpiresAt) }

// IsActive returns true if the session is valid (not revoked, not expired).
func (s *Session) IsActive() bool { return !s.IsRevoked() && !s.IsExpired() }

// ─── LoginAttempt ──────────────────────────────────────────────────────────────

// LoginAttempt records each authentication attempt for brute-force analysis.
type LoginAttempt struct {
	ID         uuid.UUID  `json:"id"          gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	TenantID   uuid.UUID  `json:"tenant_id"   gorm:"type:uuid;not null;index"`
	UserID     *uuid.UUID `json:"user_id"     gorm:"type:uuid;index"`
	IPAddress  string     `json:"ip_address"  gorm:"not null;size:45;index:idx_login_attempts_ip"`
	Email      string     `json:"email"       gorm:"not null;size:255;index:idx_login_attempts_email"`
	Success    bool       `json:"success"     gorm:"not null;index"`
	FailReason string     `json:"fail_reason" gorm:"size:255"`
	CreatedAt  time.Time  `json:"created_at"  gorm:"autoCreateTime;index:idx_login_attempts_created"`
}

// ─── Request / Response DTOs ───────────────────────────────────────────────────

// MFASetupResponse is returned from the setup endpoint.
type MFASetupResponse struct {
	Secret         string `json:"secret"`
	ProvisioningURI string `json:"provisioning_uri"`
	QRCodeHint     string `json:"qr_code_hint"`
}

// MFAVerifyRequest carries the TOTP code for verification or activation.
type MFAVerifyRequest struct {
	Code string `json:"code" binding:"required,len=6"`
}

// MFADisableRequest carries credentials needed to disable MFA.
type MFADisableRequest struct {
	Code string `json:"code" binding:"required"`
}

// MFABackupCodesResponse wraps the list of backup codes returned to the user.
type MFABackupCodesResponse struct {
	Codes     []string  `json:"codes"`
	CreatedAt time.Time `json:"created_at"`
}

// SessionListResponse is the paginated list of sessions.
type SessionListResponse struct {
	Sessions []*Session `json:"sessions"`
	Total    int64      `json:"total"`
}
