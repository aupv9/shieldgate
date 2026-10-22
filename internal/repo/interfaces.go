package repo

import (
	"context"
	"time"

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
	// Consume atomically marks the code as used and returns it. If the code was
	// already consumed it returns the stored code together with
	// models.ErrAuthCodeAlreadyUsed so the caller can revoke issued tokens.
	Consume(ctx context.Context, tenantID uuid.UUID, code string) (*models.AuthorizationCode, error)
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
	DeleteByFamilyID(ctx context.Context, tenantID, familyID uuid.UUID) error
}

// RefreshTokenRepository defines the interface for refresh token data operations
type RefreshTokenRepository interface {
	Create(ctx context.Context, token *models.RefreshToken) error
	GetByToken(ctx context.Context, tenantID uuid.UUID, token string) (*models.RefreshToken, error)
	// Revoke marks a token as revoked without deleting it, so replays of a
	// rotated token can be detected
	Revoke(ctx context.Context, tenantID uuid.UUID, token string) error
	Delete(ctx context.Context, tenantID uuid.UUID, token string) error
	DeleteExpired(ctx context.Context) error
	DeleteByUserID(ctx context.Context, tenantID, userID uuid.UUID) error
	DeleteByFamilyID(ctx context.Context, tenantID, familyID uuid.UUID) error
}

// DeviceCodeRepository defines the interface for device authorization grant
// data operations (RFC 8628)
type DeviceCodeRepository interface {
	Create(ctx context.Context, code *models.DeviceCode) error
	GetByDeviceCode(ctx context.Context, tenantID uuid.UUID, deviceCode string) (*models.DeviceCode, error)
	GetByUserCode(ctx context.Context, tenantID uuid.UUID, userCode string) (*models.DeviceCode, error)
	Update(ctx context.Context, code *models.DeviceCode) error
	Delete(ctx context.Context, tenantID uuid.UUID, deviceCode string) error
	DeleteExpired(ctx context.Context) error
}

// Repositories aggregates all repository interfaces
type Repositories struct {
	Tenant            TenantRepository
	User              UserRepository
	Client            ClientRepository
	AuthCode          AuthCodeRepository
	AccessToken       AccessTokenRepository
	RefreshToken      RefreshTokenRepository
	DeviceCode        DeviceCodeRepository
	Session           SessionRepository
	Consent           ConsentRepository
	Role              RoleRepository
	Permission        PermissionRepository
	UserRole          UserRoleRepository
	RolePermission    RolePermissionRepository
	AuditLog          AuditLogRepository
	EmailTemplate     EmailTemplateRepository
	EmailQueue        EmailQueueRepository
	EmailVerification EmailVerificationRepository
	PasswordReset     PasswordResetRepository
	Idempotency       IdempotencyRepository
}

// IdempotencyRepository stores Idempotency-Key records
type IdempotencyRepository interface {
	// Begin inserts record unless a live record holds the same (tenant,
	// principal, key). An expired record, or one left in progress since
	// before staleBefore (its request died), is replaced. It reports whether
	// record was stored; if not, existing is the record holding the key.
	Begin(ctx context.Context, record *models.IdempotencyKey, staleBefore time.Time) (stored bool, existing *models.IdempotencyKey, err error)
	// Complete saves the response of the request that holds id
	Complete(ctx context.Context, id uuid.UUID, statusCode int, contentType string, body []byte) error
	// Delete releases a key so the request can be retried
	Delete(ctx context.Context, id uuid.UUID) error
	DeleteExpired(ctx context.Context) error
}

// SessionRepository defines the interface for SSO session data operations.
// Sessions are looked up by the hash of the browser's session token.
type SessionRepository interface {
	Create(ctx context.Context, session *models.Session) error
	GetByTokenHash(ctx context.Context, tenantID uuid.UUID, tokenHash string) (*models.Session, error)
	DeleteByTokenHash(ctx context.Context, tenantID uuid.UUID, tokenHash string) error
	DeleteByUserID(ctx context.Context, tenantID, userID uuid.UUID) error
	DeleteExpired(ctx context.Context) error
}

// ConsentRepository defines the interface for consent data operations.
// There is at most one consent record per (tenant, user, client).
type ConsentRepository interface {
	Get(ctx context.Context, tenantID, userID, clientID uuid.UUID) (*models.Consent, error)
	Upsert(ctx context.Context, consent *models.Consent) error
	Delete(ctx context.Context, tenantID, userID, clientID uuid.UUID) error
}

// RoleRepository defines the interface for role data operations
type RoleRepository interface {
	Create(ctx context.Context, role *models.Role) error
	GetByID(ctx context.Context, tenantID, roleID uuid.UUID) (*models.Role, error)
	GetByName(ctx context.Context, tenantID uuid.UUID, name string) (*models.Role, error)
	Update(ctx context.Context, role *models.Role) error
	Delete(ctx context.Context, tenantID, roleID uuid.UUID) error
	List(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]*models.Role, int64, error)
	GetWithPermissions(ctx context.Context, tenantID, roleID uuid.UUID) (*models.Role, error)
}

// PermissionRepository defines the interface for permission data operations
type PermissionRepository interface {
	Create(ctx context.Context, permission *models.Permission) error
	GetByID(ctx context.Context, permissionID uuid.UUID) (*models.Permission, error)
	GetByName(ctx context.Context, name string) (*models.Permission, error)
	Update(ctx context.Context, permission *models.Permission) error
	Delete(ctx context.Context, permissionID uuid.UUID) error
	List(ctx context.Context, limit, offset int) ([]*models.Permission, int64, error)
	GetByResource(ctx context.Context, resource string) ([]*models.Permission, error)
}

// UserRoleRepository defines the interface for user-role relationship data operations
type UserRoleRepository interface {
	Create(ctx context.Context, userRole *models.UserRole) error
	GetByID(ctx context.Context, tenantID, userRoleID uuid.UUID) (*models.UserRole, error)
	GetByUserAndRole(ctx context.Context, tenantID, userID, roleID uuid.UUID) (*models.UserRole, error)
	Delete(ctx context.Context, tenantID, userID, roleID uuid.UUID) error
	GetUserRoles(ctx context.Context, tenantID, userID uuid.UUID) ([]*models.UserRole, error)
	GetRoleUsers(ctx context.Context, tenantID, roleID uuid.UUID) ([]*models.UserRole, error)
	DeleteExpired(ctx context.Context) error
}

// RolePermissionRepository defines the interface for role-permission relationship data operations
type RolePermissionRepository interface {
	Create(ctx context.Context, rolePermission *models.RolePermission) error
	GetByID(ctx context.Context, rolePermissionID uuid.UUID) (*models.RolePermission, error)
	GetByRoleAndPermission(ctx context.Context, roleID, permissionID uuid.UUID) (*models.RolePermission, error)
	Delete(ctx context.Context, roleID, permissionID uuid.UUID) error
	GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]*models.RolePermission, error)
	GetPermissionRoles(ctx context.Context, permissionID uuid.UUID) ([]*models.RolePermission, error)
}

// AuditLogRepository defines the interface for audit log data operations
type AuditLogRepository interface {
	Create(ctx context.Context, auditLog *models.AuditLog) error
	GetByID(ctx context.Context, tenantID, auditID uuid.UUID) (*models.AuditLog, error)
	Query(ctx context.Context, query *models.AuditLogQuery) ([]*models.AuditLog, int64, error)
	GetUserActivity(ctx context.Context, tenantID, userID uuid.UUID, limit, offset int) ([]*models.AuditLog, int64, error)
	GetResourceActivity(ctx context.Context, tenantID uuid.UUID, resource string, resourceID uuid.UUID, limit, offset int) ([]*models.AuditLog, int64, error)
	DeleteOldLogs(ctx context.Context, olderThan time.Time) error
}

// EmailTemplateRepository defines the interface for email template data operations
type EmailTemplateRepository interface {
	Create(ctx context.Context, template *models.EmailTemplate) error
	GetByName(ctx context.Context, tenantID uuid.UUID, name string) (*models.EmailTemplate, error)
	Update(ctx context.Context, template *models.EmailTemplate) error
	Delete(ctx context.Context, tenantID uuid.UUID, name string) error
	List(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]*models.EmailTemplate, int64, error)
}

// EmailQueueRepository defines the interface for email queue data operations
type EmailQueueRepository interface {
	Create(ctx context.Context, email *models.EmailQueue) error
	GetByID(ctx context.Context, tenantID, emailID uuid.UUID) (*models.EmailQueue, error)
	// GetPendingEmails claims up to limit due emails by moving them to
	// "sending", so concurrent workers never send the same email twice
	GetPendingEmails(ctx context.Context, limit int) ([]*models.EmailQueue, error)
	Update(ctx context.Context, email *models.EmailQueue) error
	Delete(ctx context.Context, tenantID, emailID uuid.UUID) error
	GetQueueStatus(ctx context.Context, tenantID uuid.UUID) (map[string]int, error)
	GetFailedEmails(ctx context.Context, tenantID uuid.UUID, maxAttempts int) ([]*models.EmailQueue, error)
}

// EmailVerificationRepository stores email verification codes by hash
type EmailVerificationRepository interface {
	Create(ctx context.Context, verification *models.EmailVerification) error
	GetByCodeHash(ctx context.Context, tenantID uuid.UUID, codeHash string) (*models.EmailVerification, error)
	// MarkVerified sets verified_at if it is still unset and reports whether
	// this call did so, making each code single-use under concurrency
	MarkVerified(ctx context.Context, id uuid.UUID) (bool, error)
	// DeletePendingByUserID removes the user's unverified codes
	DeletePendingByUserID(ctx context.Context, tenantID, userID uuid.UUID) error
	DeleteExpired(ctx context.Context) error
}

// PasswordResetRepository stores password reset tokens by hash
type PasswordResetRepository interface {
	Create(ctx context.Context, reset *models.PasswordReset) error
	GetByTokenHash(ctx context.Context, tenantID uuid.UUID, tokenHash string) (*models.PasswordReset, error)
	// MarkUsed sets used_at if it is still unset and reports whether this
	// call did so, making each token single-use under concurrency
	MarkUsed(ctx context.Context, id uuid.UUID) (bool, error)
	// CountSince counts the user's reset requests created after since
	CountSince(ctx context.Context, tenantID, userID uuid.UUID, since time.Time) (int64, error)
	// RevokeUnusedByUserID marks the user's outstanding reset tokens used.
	// Rows are kept so CountSince still sees them.
	RevokeUnusedByUserID(ctx context.Context, tenantID, userID uuid.UUID) error
	DeleteExpired(ctx context.Context) error
}
