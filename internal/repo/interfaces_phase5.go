package repo

import (
	"context"
	"time"

	"shieldgate/internal/models"

	"github.com/google/uuid"
)

// MFASecretRepository manages TOTP secrets.
type MFASecretRepository interface {
	Create(ctx context.Context, secret *models.MFASecret) error
	GetByUserID(ctx context.Context, tenantID, userID uuid.UUID) (*models.MFASecret, error)
	Update(ctx context.Context, secret *models.MFASecret) error
	Delete(ctx context.Context, tenantID, userID uuid.UUID) error
}

// MFABackupCodeRepository manages single-use MFA backup codes.
type MFABackupCodeRepository interface {
	CreateBatch(ctx context.Context, codes []*models.MFABackupCode) error
	GetByUserID(ctx context.Context, tenantID, userID uuid.UUID) ([]*models.MFABackupCode, error)
	GetByCodeHash(ctx context.Context, tenantID, userID uuid.UUID, hash string) (*models.MFABackupCode, error)
	MarkUsed(ctx context.Context, id uuid.UUID) error
	DeleteByUserID(ctx context.Context, tenantID, userID uuid.UUID) error
}

// SessionRepository manages authenticated user sessions.
type SessionRepository interface {
	Create(ctx context.Context, session *models.Session) error
	GetByID(ctx context.Context, tenantID, sessionID uuid.UUID) (*models.Session, error)
	GetByTokenID(ctx context.Context, tokenID string) (*models.Session, error)
	ListByUser(ctx context.Context, tenantID, userID uuid.UUID, limit, offset int) ([]*models.Session, int64, error)
	Update(ctx context.Context, session *models.Session) error
	Revoke(ctx context.Context, tenantID, sessionID uuid.UUID) error
	RevokeAll(ctx context.Context, tenantID, userID uuid.UUID) error
	DeleteExpired(ctx context.Context) error
}

// LoginAttemptRepository persists login attempt records.
type LoginAttemptRepository interface {
	Create(ctx context.Context, attempt *models.LoginAttempt) error
	CountRecent(ctx context.Context, tenantID uuid.UUID, ipAddress, email string, since time.Time) (int64, error)
	DeleteOld(ctx context.Context, before time.Time) error
}
