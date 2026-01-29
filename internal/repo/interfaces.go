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
	Tenant            TenantRepository
	User              UserRepository
	Client            ClientRepository
	AuthCode          AuthCodeRepository
	AccessToken       AccessTokenRepository
	RefreshToken      RefreshTokenRepository
	Role              RoleRepository
	Permission        PermissionRepository
	UserRole          UserRoleRepository
	RolePermission    RolePermissionRepository
	AuditLog          AuditLogRepository
	EmailTemplate     EmailTemplateRepository
	EmailQueue        EmailQueueRepository
	EmailVerification EmailVerificationRepository
	PasswordReset     PasswordResetRepository
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
	GetPendingEmails(ctx context.Context, limit int) ([]*models.EmailQueue, error)
	Update(ctx context.Context, email *models.EmailQueue) error
	Delete(ctx context.Context, tenantID, emailID uuid.UUID) error
	GetQueueStatus(ctx context.Context, tenantID uuid.UUID) (map[string]int, error)
	GetFailedEmails(ctx context.Context, tenantID uuid.UUID, maxAttempts int) ([]*models.EmailQueue, error)
}

// EmailVerificationRepository defines the interface for email verification data operations
type EmailVerificationRepository interface {
	Create(ctx context.Context, verification *models.EmailVerification) error
	GetByCode(ctx context.Context, tenantID uuid.UUID, code string) (*models.EmailVerification, error)
	GetByUserID(ctx context.Context, tenantID, userID uuid.UUID) (*models.EmailVerification, error)
	Update(ctx context.Context, verification *models.EmailVerification) error
	Delete(ctx context.Context, tenantID uuid.UUID, code string) error
	DeleteExpired(ctx context.Context) error
}

// PasswordResetRepository defines the interface for password reset data operations
type PasswordResetRepository interface {
	Create(ctx context.Context, reset *models.PasswordReset) error
	GetByToken(ctx context.Context, tenantID uuid.UUID, token string) (*models.PasswordReset, error)
	GetByUserID(ctx context.Context, tenantID, userID uuid.UUID) ([]*models.PasswordReset, error)
	Update(ctx context.Context, reset *models.PasswordReset) error
	Delete(ctx context.Context, tenantID uuid.UUID, token string) error
	DeleteExpired(ctx context.Context) error
}
