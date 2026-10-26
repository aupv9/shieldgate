package database

import (
	"fmt"

	"github.com/sirupsen/logrus"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Initialize initializes the database connection using GORM
func Initialize(databaseURL string) (*gorm.DB, error) {
	logrus.Info("Connecting to database...")

	// Configure GORM logger
	gormLogger := logger.Default.LogMode(logger.Info)

	// Open database connection with GORM
	db, err := gorm.Open(postgres.Open(databaseURL), &gorm.Config{
		Logger:                                   gormLogger,
		DisableForeignKeyConstraintWhenMigrating: true, // Disable foreign key constraints during migration
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open database connection: %w", err)
	}

	// Get underlying sql.DB to configure connection pool
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get underlying sql.DB: %w", err)
	}

	// Set connection pool settings
	sqlDB.SetMaxOpenConns(25)
	sqlDB.SetMaxIdleConns(5)

	logrus.Info("Database connection established")
	return db, nil
}

// Migrate runs database migrations using manual SQL
func Migrate(db *gorm.DB) error {
	logrus.Info("Running database migrations...")

	// Create tables manually with SQL to avoid GORM foreign key inference
	migrations := []string{
		// Create tenants table
		`CREATE TABLE IF NOT EXISTS tenants (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			name VARCHAR(255) NOT NULL,
			domain VARCHAR(255) NOT NULL,
			is_active BOOLEAN NOT NULL DEFAULT true,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			deleted_at TIMESTAMP WITH TIME ZONE
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_tenants_domain ON tenants(domain) WHERE deleted_at IS NULL`,
		`CREATE INDEX IF NOT EXISTS idx_tenants_deleted_at ON tenants(deleted_at)`,

		// Create users table
		`CREATE TABLE IF NOT EXISTS users (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL,
			username VARCHAR(255) NOT NULL,
			email VARCHAR(255) NOT NULL,
			password_hash VARCHAR(255) NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			deleted_at TIMESTAMP WITH TIME ZONE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_users_tenant_id ON users(tenant_id)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_tenant_username ON users(tenant_id, username) WHERE deleted_at IS NULL`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_tenant_email ON users(tenant_id, email) WHERE deleted_at IS NULL`,
		`CREATE INDEX IF NOT EXISTS idx_users_deleted_at ON users(deleted_at)`,

		// Create clients table
		`CREATE TABLE IF NOT EXISTS clients (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL,
			client_id VARCHAR(255) NOT NULL,
			client_secret VARCHAR(255),
			name VARCHAR(255) NOT NULL,
			redirect_uris JSONB NOT NULL DEFAULT '[]',
			grant_types JSONB NOT NULL DEFAULT '[]',
			scopes JSONB NOT NULL DEFAULT '[]',
			is_public BOOLEAN NOT NULL DEFAULT false,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			deleted_at TIMESTAMP WITH TIME ZONE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_clients_tenant_id ON clients(tenant_id)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_clients_tenant_client_id ON clients(tenant_id, client_id) WHERE deleted_at IS NULL`,
		`CREATE INDEX IF NOT EXISTS idx_clients_deleted_at ON clients(deleted_at)`,

		// Create authorization_codes table
		`CREATE TABLE IF NOT EXISTS authorization_codes (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL,
			code VARCHAR(255) NOT NULL,
			client_id UUID NOT NULL,
			user_id UUID NOT NULL,
			redirect_uri VARCHAR(255) NOT NULL,
			scope TEXT,
			code_challenge VARCHAR(255),
			code_challenge_method VARCHAR(50),
			used_at TIMESTAMP WITH TIME ZONE,
			expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_authorization_codes_code ON authorization_codes(code)`,
		`CREATE INDEX IF NOT EXISTS idx_authorization_codes_tenant_id ON authorization_codes(tenant_id)`,
		`CREATE INDEX IF NOT EXISTS idx_authorization_codes_client_id ON authorization_codes(client_id)`,
		`CREATE INDEX IF NOT EXISTS idx_authorization_codes_user_id ON authorization_codes(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_authorization_codes_expires_at ON authorization_codes(expires_at)`,

		// Create access_tokens table
		`CREATE TABLE IF NOT EXISTS access_tokens (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL,
			token VARCHAR(255) NOT NULL,
			client_id UUID NOT NULL,
			user_id UUID NOT NULL,
			family_id UUID,
			scope TEXT,
			expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_access_tokens_token ON access_tokens(token)`,
		`CREATE INDEX IF NOT EXISTS idx_access_tokens_tenant_id ON access_tokens(tenant_id)`,
		`CREATE INDEX IF NOT EXISTS idx_access_tokens_client_id ON access_tokens(client_id)`,
		`CREATE INDEX IF NOT EXISTS idx_access_tokens_user_id ON access_tokens(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_access_tokens_expires_at ON access_tokens(expires_at)`,

		// Create refresh_tokens table
		`CREATE TABLE IF NOT EXISTS refresh_tokens (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL,
			token VARCHAR(255) NOT NULL,
			client_id UUID NOT NULL,
			user_id UUID NOT NULL,
			family_id UUID,
			scope TEXT,
			revoked_at TIMESTAMP WITH TIME ZONE,
			expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_refresh_tokens_token ON refresh_tokens(token)`,
		`CREATE INDEX IF NOT EXISTS idx_refresh_tokens_tenant_id ON refresh_tokens(tenant_id)`,
		`CREATE INDEX IF NOT EXISTS idx_refresh_tokens_client_id ON refresh_tokens(client_id)`,
		`CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at ON refresh_tokens(expires_at)`,

		// Create device_codes table (RFC 8628 device authorization grant)
		`CREATE TABLE IF NOT EXISTS device_codes (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL,
			device_code VARCHAR(255) NOT NULL,
			user_code VARCHAR(32) NOT NULL,
			client_id UUID NOT NULL,
			user_id UUID,
			scope TEXT,
			status VARCHAR(20) NOT NULL DEFAULT 'pending',
			"interval" INTEGER NOT NULL DEFAULT 5,
			last_polled_at TIMESTAMP WITH TIME ZONE,
			expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_device_codes_device_code ON device_codes(device_code)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_device_codes_user_code ON device_codes(user_code)`,
		`CREATE INDEX IF NOT EXISTS idx_device_codes_tenant_id ON device_codes(tenant_id)`,
		`CREATE INDEX IF NOT EXISTS idx_device_codes_expires_at ON device_codes(expires_at)`,

		// Create RBAC tables. granted_by has no FK to users because grants
		// may be issued by the system (tenant ID) or a client-credentials token
		`CREATE TABLE IF NOT EXISTS permissions (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			name VARCHAR(255) NOT NULL,
			display_name VARCHAR(255) NOT NULL,
			description TEXT,
			resource VARCHAR(255) NOT NULL,
			action VARCHAR(255) NOT NULL,
			is_system BOOLEAN NOT NULL DEFAULT false,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			deleted_at TIMESTAMP WITH TIME ZONE
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_permissions_name ON permissions(name) WHERE deleted_at IS NULL`,
		`CREATE INDEX IF NOT EXISTS idx_permissions_resource ON permissions(resource)`,
		`CREATE INDEX IF NOT EXISTS idx_permissions_deleted_at ON permissions(deleted_at)`,

		`CREATE TABLE IF NOT EXISTS roles (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL,
			name VARCHAR(255) NOT NULL,
			display_name VARCHAR(255) NOT NULL,
			description TEXT,
			is_system BOOLEAN NOT NULL DEFAULT false,
			is_active BOOLEAN NOT NULL DEFAULT true,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			deleted_at TIMESTAMP WITH TIME ZONE
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_roles_tenant_name ON roles(tenant_id, name) WHERE deleted_at IS NULL`,
		`CREATE INDEX IF NOT EXISTS idx_roles_tenant_id ON roles(tenant_id)`,
		`CREATE INDEX IF NOT EXISTS idx_roles_deleted_at ON roles(deleted_at)`,

		`CREATE TABLE IF NOT EXISTS user_roles (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL,
			user_id UUID NOT NULL,
			role_id UUID NOT NULL,
			granted_by UUID NOT NULL,
			granted_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			expires_at TIMESTAMP WITH TIME ZONE
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_user_roles_unique ON user_roles(tenant_id, user_id, role_id)`,
		`CREATE INDEX IF NOT EXISTS idx_user_roles_role_id ON user_roles(role_id)`,
		`CREATE INDEX IF NOT EXISTS idx_user_roles_expires_at ON user_roles(expires_at)`,

		`CREATE TABLE IF NOT EXISTS role_permissions (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			role_id UUID NOT NULL,
			permission_id UUID NOT NULL,
			granted_by UUID NOT NULL,
			granted_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_role_permissions_unique ON role_permissions(role_id, permission_id)`,
		`CREATE INDEX IF NOT EXISTS idx_role_permissions_permission_id ON role_permissions(permission_id)`,

		// Create audit_logs table
		`CREATE TABLE IF NOT EXISTS audit_logs (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL,
			user_id UUID,
			client_id UUID,
			action VARCHAR(255) NOT NULL,
			resource VARCHAR(255) NOT NULL,
			resource_id UUID,
			ip_address VARCHAR(45),
			user_agent TEXT,
			request_id VARCHAR(255),
			success BOOLEAN NOT NULL,
			error_code VARCHAR(255),
			error_message TEXT,
			metadata JSONB DEFAULT '{}',
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_created ON audit_logs(tenant_id, created_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_user ON audit_logs(tenant_id, user_id, created_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_resource ON audit_logs(tenant_id, resource, resource_id, created_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_action ON audit_logs(tenant_id, action, created_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at)`,

		// Seed the system permissions checked by the management API authorizer.
		// Tenant and permission-catalog changes are super-admin only, so they
		// have no grantable permission. "manage" covers every action.
		`INSERT INTO permissions (name, display_name, description, resource, action, is_system) VALUES
			('users.create', 'Create Users', 'Create new users', 'user', 'create', true),
			('users.read', 'Read Users', 'View user information', 'user', 'read', true),
			('users.update', 'Update Users', 'Update user information', 'user', 'update', true),
			('users.delete', 'Delete Users', 'Delete users', 'user', 'delete', true),
			('users.manage', 'Manage Users', 'Full user management access', 'user', 'manage', true),
			('clients.create', 'Create Clients', 'Create OAuth clients', 'client', 'create', true),
			('clients.read', 'Read Clients', 'View OAuth clients', 'client', 'read', true),
			('clients.update', 'Update Clients', 'Update OAuth clients', 'client', 'update', true),
			('clients.delete', 'Delete Clients', 'Delete OAuth clients', 'client', 'delete', true),
			('clients.manage', 'Manage Clients', 'Full client management access', 'client', 'manage', true),
			('roles.create', 'Create Roles', 'Create new roles', 'role', 'create', true),
			('roles.read', 'Read Roles', 'View roles', 'role', 'read', true),
			('roles.update', 'Update Roles', 'Update roles and their permissions', 'role', 'update', true),
			('roles.delete', 'Delete Roles', 'Delete roles', 'role', 'delete', true),
			('roles.assign', 'Assign Roles', 'Assign roles to users', 'role', 'assign', true),
			('roles.manage', 'Manage Roles', 'Full role management access', 'role', 'manage', true),
			('permissions.read', 'Read Permissions', 'View the permission catalog', 'permission', 'read', true),
			('audit.read', 'Read Audit Logs', 'View audit logs', 'audit', 'read', true)
		ON CONFLICT (name) WHERE deleted_at IS NULL DO NOTHING`,

		// Phase 1 hardening: columns for token hashing, rotation families,
		// and authorization-code reuse detection on databases created before
		// these fields existed (ALTER ... IF NOT EXISTS keeps this idempotent)
		`ALTER TABLE authorization_codes ADD COLUMN IF NOT EXISTS used_at TIMESTAMP WITH TIME ZONE`,
		`ALTER TABLE access_tokens ADD COLUMN IF NOT EXISTS family_id UUID`,
		`ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS family_id UUID`,
		`ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS scope TEXT`,
		`ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMP WITH TIME ZONE`,
		`CREATE INDEX IF NOT EXISTS idx_access_tokens_family_id ON access_tokens(family_id)`,
		`CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family_id ON refresh_tokens(family_id)`,

		// OIDC: nonce and auth_time travel from the authorization request to
		// the ID token; refresh tokens keep the original auth_time
		`ALTER TABLE authorization_codes ADD COLUMN IF NOT EXISTS nonce TEXT`,
		`ALTER TABLE authorization_codes ADD COLUMN IF NOT EXISTS auth_time TIMESTAMP WITH TIME ZONE`,
		`ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS auth_time TIMESTAMP WITH TIME ZONE`,
		`ALTER TABLE device_codes ADD COLUMN IF NOT EXISTS auth_time TIMESTAMP WITH TIME ZONE`,

		// SSO sessions: the cookie holds a random token, only its hash is stored
		`CREATE TABLE IF NOT EXISTS sessions (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL,
			user_id UUID NOT NULL,
			token_hash VARCHAR(255) NOT NULL,
			auth_time TIMESTAMP WITH TIME ZONE NOT NULL,
			ip_address VARCHAR(45),
			user_agent TEXT,
			expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_tenant_user ON sessions(tenant_id, user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)`,

		// Consent: one record per (tenant, user, client) holding granted scopes
		`CREATE TABLE IF NOT EXISTS consents (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL,
			user_id UUID NOT NULL,
			client_id UUID NOT NULL,
			scope TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_consents_tenant_user_client ON consents(tenant_id, user_id, client_id)`,

		// RP-initiated logout redirect allow-list
		`ALTER TABLE clients ADD COLUMN IF NOT EXISTS post_logout_redirect_uris JSONB NOT NULL DEFAULT '[]'`,

		// User account state used by models.User; previously only in the
		// manual migrations/001_priority_1_features.sql, so fresh databases
		// could not insert users
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS status VARCHAR(20) NOT NULL DEFAULT 'pending'`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT FALSE`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verification_code VARCHAR(255)`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verification_expires_at TIMESTAMP WITH TIME ZONE`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS phone_number VARCHAR(50)`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS phone_verified BOOLEAN NOT NULL DEFAULT FALSE`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS first_name VARCHAR(255)`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS last_name VARCHAR(255)`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar VARCHAR(500)`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS locale VARCHAR(10) DEFAULT 'en'`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS timezone VARCHAR(50) DEFAULT 'UTC'`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMP WITH TIME ZONE`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_ip VARCHAR(45)`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_login_attempts INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_at TIMESTAMP WITH TIME ZONE`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMP WITH TIME ZONE`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS password_reset_token VARCHAR(255)`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS password_reset_expires_at TIMESTAMP WITH TIME ZONE`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS metadata JSONB DEFAULT '{}'`,
		`CREATE INDEX IF NOT EXISTS idx_users_status ON users(status)`,

		// Email system
		`CREATE TABLE IF NOT EXISTS email_templates (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL,
			name VARCHAR(255) NOT NULL,
			subject VARCHAR(500) NOT NULL,
			body_html TEXT,
			body_text TEXT,
			variables JSONB DEFAULT '[]',
			is_active BOOLEAN NOT NULL DEFAULT TRUE,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			deleted_at TIMESTAMP WITH TIME ZONE
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_email_templates_tenant_name ON email_templates(tenant_id, name) WHERE deleted_at IS NULL`,

		`CREATE TABLE IF NOT EXISTS email_queue (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL,
			user_id UUID,
			to_email VARCHAR(255) NOT NULL,
			to_name VARCHAR(255),
			from_email VARCHAR(255) NOT NULL,
			from_name VARCHAR(255),
			subject VARCHAR(500) NOT NULL,
			body_html TEXT,
			body_text TEXT,
			status VARCHAR(50) NOT NULL DEFAULT 'pending',
			priority INTEGER NOT NULL DEFAULT 5,
			attempts INTEGER NOT NULL DEFAULT 0,
			max_attempts INTEGER NOT NULL DEFAULT 3,
			last_error TEXT,
			scheduled_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			sent_at TIMESTAMP WITH TIME ZONE,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_email_queue_status_scheduled ON email_queue(status, scheduled_at)`,
		`CREATE INDEX IF NOT EXISTS idx_email_queue_tenant_id ON email_queue(tenant_id)`,

		// Verification codes and reset tokens: only the SHA-256 hash is
		// stored. Rows from the old plaintext layout are discarded.
		`CREATE TABLE IF NOT EXISTS email_verifications (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL,
			user_id UUID NOT NULL,
			email VARCHAR(255) NOT NULL,
			code_hash VARCHAR(255),
			expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
			verified_at TIMESTAMP WITH TIME ZONE,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		)`,
		`ALTER TABLE email_verifications ADD COLUMN IF NOT EXISTS code_hash VARCHAR(255)`,
		`ALTER TABLE email_verifications DROP COLUMN IF EXISTS code`,
		`DELETE FROM email_verifications WHERE code_hash IS NULL`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_email_verifications_code_hash ON email_verifications(code_hash)`,
		`CREATE INDEX IF NOT EXISTS idx_email_verifications_tenant_user ON email_verifications(tenant_id, user_id)`,

		`CREATE TABLE IF NOT EXISTS password_resets (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL,
			user_id UUID NOT NULL,
			token_hash VARCHAR(255),
			expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
			used_at TIMESTAMP WITH TIME ZONE,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		)`,
		`ALTER TABLE password_resets ADD COLUMN IF NOT EXISTS token_hash VARCHAR(255)`,
		`ALTER TABLE password_resets DROP COLUMN IF EXISTS token`,
		`DELETE FROM password_resets WHERE token_hash IS NULL`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_password_resets_token_hash ON password_resets(token_hash)`,
		`CREATE INDEX IF NOT EXISTS idx_password_resets_tenant_user ON password_resets(tenant_id, user_id, created_at)`,

		// Idempotency-Key records for management API POSTs
		`CREATE TABLE IF NOT EXISTS idempotency_keys (
			id UUID PRIMARY KEY,
			tenant_id UUID NOT NULL,
			principal VARCHAR(255) NOT NULL,
			idem_key VARCHAR(255) NOT NULL,
			method VARCHAR(10) NOT NULL,
			path VARCHAR(2048) NOT NULL,
			request_hash VARCHAR(64) NOT NULL,
			status_code INTEGER NOT NULL DEFAULT 0,
			response_content_type VARCHAR(255),
			response_body BYTEA,
			created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			expires_at TIMESTAMP WITH TIME ZONE NOT NULL
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_idempotency_keys_scope ON idempotency_keys(tenant_id, principal, idem_key)`,
		`CREATE INDEX IF NOT EXISTS idx_idempotency_keys_expires_at ON idempotency_keys(expires_at)`,

		// MFA: TOTP authenticators (secret sealed with AES-GCM) and
		// recovery codes (keyed hash only)
		`CREATE TABLE IF NOT EXISTS user_mfa (
			user_id UUID PRIMARY KEY,
			tenant_id UUID NOT NULL,
			totp_secret TEXT NOT NULL,
			confirmed_at TIMESTAMP WITH TIME ZONE,
			last_used_step BIGINT NOT NULL DEFAULT 0,
			failed_attempts INTEGER NOT NULL DEFAULT 0,
			locked_until TIMESTAMP WITH TIME ZONE,
			created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_user_mfa_tenant ON user_mfa(tenant_id)`,
		`CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
			id UUID PRIMARY KEY,
			tenant_id UUID NOT NULL,
			user_id UUID NOT NULL,
			code_hash VARCHAR(64) NOT NULL,
			used_at TIMESTAMP WITH TIME ZONE,
			created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_mfa_recovery_codes_user_hash ON mfa_recovery_codes(tenant_id, user_id, code_hash)`,

		// amr (RFC 8176) travels with auth_time from login to the ID token
		`ALTER TABLE sessions ADD COLUMN IF NOT EXISTS amr JSONB NOT NULL DEFAULT '[]'`,
		`ALTER TABLE authorization_codes ADD COLUMN IF NOT EXISTS amr JSONB`,
		`ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS amr JSONB`,
		`ALTER TABLE device_codes ADD COLUMN IF NOT EXISTS amr JSONB`,

		// Dynamic client registration (RFC 7591/7592)
		`ALTER TABLE clients ADD COLUMN IF NOT EXISTS token_endpoint_auth_method VARCHAR(50) NOT NULL DEFAULT 'client_secret_basic'`,
		`UPDATE clients SET token_endpoint_auth_method = 'none' WHERE is_public AND token_endpoint_auth_method = 'client_secret_basic'`,
		`ALTER TABLE clients ADD COLUMN IF NOT EXISTS dynamically_registered BOOLEAN NOT NULL DEFAULT FALSE`,
		`ALTER TABLE clients ADD COLUMN IF NOT EXISTS registration_access_token_hash VARCHAR(255)`,
		`CREATE TABLE IF NOT EXISTS initial_access_tokens (
			id UUID PRIMARY KEY,
			tenant_id UUID NOT NULL,
			token_hash VARCHAR(255) NOT NULL,
			description VARCHAR(255),
			scopes JSONB NOT NULL DEFAULT '[]',
			max_uses INTEGER NOT NULL,
			uses INTEGER NOT NULL DEFAULT 0,
			created_by UUID,
			expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
			revoked_at TIMESTAMP WITH TIME ZONE,
			created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_initial_access_tokens_hash ON initial_access_tokens(token_hash)`,
		`CREATE INDEX IF NOT EXISTS idx_initial_access_tokens_tenant ON initial_access_tokens(tenant_id, created_at DESC)`,
	}

	// Execute each migration
	for i, migration := range migrations {
		logrus.Infof("Executing migration %d/%d", i+1, len(migrations))
		if err := db.Exec(migration).Error; err != nil {
			return fmt.Errorf("failed to execute migration %d: %w", i+1, err)
		}
	}

	logrus.Info("Database migrations completed successfully")
	return nil
}
