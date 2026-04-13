package services

import (
	"context"
	"time"

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

	// Enhanced User Management
	UpdateStatus(ctx context.Context, tenantID, userID uuid.UUID, status models.UserStatus) error
	LockUser(ctx context.Context, tenantID, userID uuid.UUID, reason string, lockedUntil *time.Time) error
	UnlockUser(ctx context.Context, tenantID, userID uuid.UUID) error
	SuspendUser(ctx context.Context, tenantID, userID uuid.UUID, reason string) error
	ActivateUser(ctx context.Context, tenantID, userID uuid.UUID) error

	// Email Verification
	SendVerificationEmail(ctx context.Context, tenantID, userID uuid.UUID) error
	VerifyEmail(ctx context.Context, tenantID uuid.UUID, code string) (*models.User, error)

	// Password Reset
	RequestPasswordReset(ctx context.Context, tenantID uuid.UUID, email string) error
	ResetPassword(ctx context.Context, tenantID uuid.UUID, token, newPassword string) (*models.User, error)

	// Login Tracking
	RecordLoginAttempt(ctx context.Context, tenantID uuid.UUID, email, ipAddress string, success bool) error
	GetLoginHistory(ctx context.Context, tenantID, userID uuid.UUID, limit, offset int) (*models.PaginatedResponse, error)
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
	GenerateAuthorizationCode(ctx context.Context, tenantID, clientID, userID uuid.UUID, redirectURI, scope, codeChallenge, codeChallengeMethod string) (*models.AuthorizationCode, error)
	ExchangeAuthorizationCode(ctx context.Context, tenantID uuid.UUID, code, clientID, clientSecret, redirectURI, codeVerifier string) (*models.TokenResponse, error)
	GenerateTokens(ctx context.Context, tenantID, clientID, userID uuid.UUID, scope string, includeIDToken bool) (*models.TokenResponse, error)
	RefreshTokens(ctx context.Context, tenantID uuid.UUID, refreshToken, clientID, clientSecret string) (*models.TokenResponse, error)
	RevokeToken(ctx context.Context, tenantID uuid.UUID, token, tokenTypeHint string) error
	IntrospectToken(ctx context.Context, tenantID uuid.UUID, token string) (*models.IntrospectionResponse, error)
	ValidateAccessToken(ctx context.Context, tenantID uuid.UUID, token string) (*models.JWTClaims, error)
	ValidatePKCE(codeVerifier, codeChallenge, method string) bool
	GenerateIDToken(ctx context.Context, user *models.User, clientID string) (string, error)
	GetUserInfo(ctx context.Context, tenantID uuid.UUID, accessToken string) (*models.UserInfo, error)
	GetDiscoveryDocument(ctx context.Context) (*models.OpenIDConfiguration, error)
	CleanupExpiredTokens(ctx context.Context) error
}

// MFAService manages TOTP-based multi-factor authentication.
type MFAService interface {
	// Setup generates a new TOTP secret for the user but does NOT enable MFA yet.
	Setup(ctx context.Context, tenantID, userID uuid.UUID, issuer, accountName string) (*models.MFASetupResponse, error)
	// VerifyAndEnable validates the first TOTP code and enables MFA.
	VerifyAndEnable(ctx context.Context, tenantID, userID uuid.UUID, code string) error
	// Disable turns off MFA after verifying either a TOTP code or backup code.
	Disable(ctx context.Context, tenantID, userID uuid.UUID, code string) error
	// ValidateCode returns true if the given TOTP code (or backup code) is valid.
	ValidateCode(ctx context.Context, tenantID, userID uuid.UUID, code string) (bool, error)
	// IsEnabled reports whether the user has MFA active.
	IsEnabled(ctx context.Context, tenantID, userID uuid.UUID) (bool, error)
	// GetBackupCodes returns the user's existing backup code records.
	GetBackupCodes(ctx context.Context, tenantID, userID uuid.UUID) ([]*models.MFABackupCode, error)
	// RegenerateBackupCodes replaces all backup codes and returns the plain-text values.
	RegenerateBackupCodes(ctx context.Context, tenantID, userID uuid.UUID) ([]string, error)
}

// SessionService manages authenticated user sessions.
type SessionService interface {
	Create(ctx context.Context, tenantID, userID uuid.UUID, tokenID, ipAddress, userAgent, deviceName string, expiresAt time.Time) (*models.Session, error)
	GetByID(ctx context.Context, tenantID, sessionID uuid.UUID) (*models.Session, error)
	GetByTokenID(ctx context.Context, tokenID string) (*models.Session, error)
	ListByUser(ctx context.Context, tenantID, userID uuid.UUID, limit, offset int) (*models.SessionListResponse, error)
	Revoke(ctx context.Context, tenantID, sessionID uuid.UUID) error
	RevokeAll(ctx context.Context, tenantID, userID uuid.UUID) error
	UpdateLastActive(ctx context.Context, sessionID uuid.UUID) error
	CleanupExpired(ctx context.Context) error
}

// Services aggregates all service interfaces
type Services struct {
	Tenant     TenantService
	User       UserService
	Client     ClientService
	Auth       AuthService
	MFA        MFAService
	Session    SessionService
}

// --- legacy service interfaces (used by phase-2/3 handlers, kept for compilation) ---

// RoleService defines the interface for RBAC role management
type RoleService interface {
	Create(ctx context.Context, tenantID uuid.UUID, req *models.CreateRoleRequest) (*models.Role, error)
	GetByID(ctx context.Context, tenantID, roleID uuid.UUID) (*models.Role, error)
	GetByName(ctx context.Context, tenantID uuid.UUID, name string) (*models.Role, error)
	Update(ctx context.Context, tenantID, roleID uuid.UUID, req *models.UpdateRoleRequest) (*models.Role, error)
	Delete(ctx context.Context, tenantID, roleID uuid.UUID) error
	List(ctx context.Context, tenantID uuid.UUID, limit, offset int) (*models.PaginatedResponse, error)
	AddPermission(ctx context.Context, tenantID, roleID, permissionID, grantedBy uuid.UUID) error
	RemovePermission(ctx context.Context, tenantID, roleID, permissionID uuid.UUID) error
	GetPermissions(ctx context.Context, tenantID, roleID uuid.UUID) ([]*models.Permission, error)
	AssignToUser(ctx context.Context, tenantID, roleID, userID, grantedBy uuid.UUID, expiresAt *time.Time) error
	RevokeFromUser(ctx context.Context, tenantID, roleID, userID uuid.UUID) error
	GetUserRoles(ctx context.Context, tenantID, userID uuid.UUID) ([]*models.Role, error)
}

// PermissionService defines the interface for RBAC permission management
type PermissionService interface {
	Create(ctx context.Context, req *models.CreatePermissionRequest) (*models.Permission, error)
	GetByID(ctx context.Context, permissionID uuid.UUID) (*models.Permission, error)
	GetByName(ctx context.Context, name string) (*models.Permission, error)
	Update(ctx context.Context, permissionID uuid.UUID, req *models.UpdatePermissionRequest) (*models.Permission, error)
	Delete(ctx context.Context, permissionID uuid.UUID) error
	List(ctx context.Context, limit, offset int) (*models.PaginatedResponse, error)
	HasPermission(ctx context.Context, tenantID, userID uuid.UUID, resource, action string) (bool, error)
	GetUserPermissions(ctx context.Context, tenantID, userID uuid.UUID) ([]*models.Permission, error)
}

// AuditService defines the interface for audit logging
type AuditService interface {
	Log(ctx context.Context, entry *models.AuditLog) error
	LogUserAction(ctx context.Context, tenantID, userID uuid.UUID, action models.AuditAction, resource string, resourceID *uuid.UUID, success bool, metadata map[string]interface{}) error
	LogClientAction(ctx context.Context, tenantID, clientID uuid.UUID, action models.AuditAction, resource string, resourceID *uuid.UUID, success bool, metadata map[string]interface{}) error
	LogSystemAction(ctx context.Context, tenantID uuid.UUID, action models.AuditAction, resource string, resourceID *uuid.UUID, success bool, metadata map[string]interface{}) error
	Query(ctx context.Context, query *models.AuditLogQuery) (*models.PaginatedResponse, error)
	GetByID(ctx context.Context, tenantID, auditID uuid.UUID) (*models.AuditLog, error)
	GetUserActivity(ctx context.Context, tenantID, userID uuid.UUID, limit, offset int) (*models.PaginatedResponse, error)
	GetResourceActivity(ctx context.Context, tenantID uuid.UUID, resource string, resourceID uuid.UUID, limit, offset int) (*models.PaginatedResponse, error)
}

// EmailService defines the interface for email management
type EmailService interface {
	CreateTemplate(ctx context.Context, tenantID uuid.UUID, template *models.EmailTemplate) error
	GetTemplate(ctx context.Context, tenantID uuid.UUID, name string) (*models.EmailTemplate, error)
	UpdateTemplate(ctx context.Context, tenantID uuid.UUID, name string, template *models.EmailTemplate) error
	DeleteTemplate(ctx context.Context, tenantID uuid.UUID, name string) error
	ListTemplates(ctx context.Context, tenantID uuid.UUID, limit, offset int) (*models.PaginatedResponse, error)
	SendEmail(ctx context.Context, tenantID uuid.UUID, req *models.SendEmailRequest) error
	SendTemplateEmail(ctx context.Context, tenantID uuid.UUID, toEmail, toName, templateName string, variables map[string]string, priority int) error
	ProcessQueue(ctx context.Context) error
	GetQueueStatus(ctx context.Context, tenantID uuid.UUID) (map[string]int, error)
	RetryFailedEmails(ctx context.Context, tenantID uuid.UUID, maxAttempts int) error
	SendVerificationEmail(ctx context.Context, tenantID, userID uuid.UUID) error
	VerifyEmail(ctx context.Context, tenantID uuid.UUID, code string) (*models.User, error)
	SendPasswordResetEmail(ctx context.Context, tenantID uuid.UUID, email string) error
	ResetPassword(ctx context.Context, tenantID uuid.UUID, token, newPassword string) (*models.User, error)
}
