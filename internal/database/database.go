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
