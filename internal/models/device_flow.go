package models

import (
	"errors"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// DeviceCodeStatus enumerates the lifecycle states of a device authorization request.
type DeviceCodeStatus string

const (
	DeviceCodeStatusPending    DeviceCodeStatus = "pending"
	DeviceCodeStatusAuthorized DeviceCodeStatus = "authorized"
	DeviceCodeStatusDenied     DeviceCodeStatus = "denied"
)

// DeviceCode holds an RFC 8628 device+user code pair during device authorization.
type DeviceCode struct {
	ID              uuid.UUID        `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	TenantID        uuid.UUID        `json:"tenant_id" gorm:"type:uuid;not null;index"`
	ClientID        uuid.UUID        `json:"client_id" gorm:"type:uuid;not null;index"`
	DeviceCodeValue string           `json:"-" gorm:"column:device_code;not null;size:255;uniqueIndex"`
	UserCode        string           `json:"user_code" gorm:"not null;size:20;uniqueIndex"`
	VerificationURI string           `json:"verification_uri" gorm:"not null;size:500"`
	Scope           string           `json:"scope" gorm:"type:text"`
	Status          DeviceCodeStatus `json:"status" gorm:"not null;size:50;default:'pending';index"`
	UserID          *uuid.UUID       `json:"user_id,omitempty" gorm:"type:uuid;index"`
	ExpiresAt       time.Time        `json:"expires_at" gorm:"not null;index"`
	LastPolledAt    *time.Time       `json:"last_polled_at,omitempty"`
	Interval        int              `json:"interval" gorm:"not null;default:5"`
	CreatedAt       time.Time        `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt       time.Time        `json:"updated_at" gorm:"autoUpdateTime"`
	DeletedAt       gorm.DeletedAt   `json:"-" gorm:"index"`
}

// IsExpired reports whether the device code has passed its expiry time.
func (dc *DeviceCode) IsExpired() bool {
	return time.Now().After(dc.ExpiresAt)
}

// DeviceAuthorizationResponse is returned to the device on POST /oauth/device/code.
type DeviceAuthorizationResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// Sentinel errors for the device authorization flow.
var (
	ErrDeviceCodeNotFound = errors.New("device code not found")
	ErrDeviceCodeExpired  = errors.New("device code expired")
	ErrDeviceCodeDenied   = errors.New("access_denied")
	ErrDeviceCodePending  = errors.New("authorization_pending")
	ErrDeviceCodeSlowDown = errors.New("slow_down")
)
