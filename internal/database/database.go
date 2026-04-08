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
			expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_refresh_tokens_token ON refresh_tokens(token)`,
		`CREATE INDEX IF NOT EXISTS idx_refresh_tokens_tenant_id ON refresh_tokens(tenant_id)`,
		`CREATE INDEX IF NOT EXISTS idx_refresh_tokens_client_id ON refresh_tokens(client_id)`,
		`CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at ON refresh_tokens(expires_at)`,

		// ── Phase 1 Features ────────────────────────────────────────────────

		// Enhanced user management columns
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS status VARCHAR(20) NOT NULL DEFAULT 'pending'`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT FALSE`,
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
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS metadata JSONB DEFAULT '{}'`,
		`CREATE INDEX IF NOT EXISTS idx_users_status ON users(status)`,
		`CREATE INDEX IF NOT EXISTS idx_users_email_verified ON users(email_verified)`,

		// Permissions table
		`CREATE TABLE IF NOT EXISTS permissions (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			name VARCHAR(255) NOT NULL UNIQUE,
			display_name VARCHAR(255) NOT NULL,
			description TEXT,
			resource VARCHAR(255) NOT NULL,
			action VARCHAR(255) NOT NULL,
			is_system BOOLEAN NOT NULL DEFAULT FALSE,
			created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			deleted_at TIMESTAMP WITH TIME ZONE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_permissions_resource ON permissions(resource)`,
		`CREATE INDEX IF NOT EXISTS idx_permissions_action ON permissions(action)`,

		// Roles table
		`CREATE TABLE IF NOT EXISTS roles (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL,
			name VARCHAR(255) NOT NULL,
			display_name VARCHAR(255) NOT NULL,
			description TEXT,
			is_system BOOLEAN NOT NULL DEFAULT FALSE,
			is_active BOOLEAN NOT NULL DEFAULT TRUE,
			created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			deleted_at TIMESTAMP WITH TIME ZONE
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_roles_tenant_name ON roles(tenant_id, name) WHERE deleted_at IS NULL`,
		`CREATE INDEX IF NOT EXISTS idx_roles_tenant_id ON roles(tenant_id)`,

		// User roles junction table
		`CREATE TABLE IF NOT EXISTS user_roles (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL,
			user_id UUID NOT NULL,
			role_id UUID NOT NULL,
			granted_by UUID NOT NULL,
			granted_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			expires_at TIMESTAMP WITH TIME ZONE
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_user_roles_user_role ON user_roles(tenant_id, user_id, role_id)`,
		`CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON user_roles(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_user_roles_role_id ON user_roles(role_id)`,

		// Role permissions junction table
		`CREATE TABLE IF NOT EXISTS role_permissions (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			role_id UUID NOT NULL,
			permission_id UUID NOT NULL,
			granted_by UUID NOT NULL,
			granted_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_role_permissions_role_perm ON role_permissions(role_id, permission_id)`,
		`CREATE INDEX IF NOT EXISTS idx_role_permissions_role_id ON role_permissions(role_id)`,
		`CREATE INDEX IF NOT EXISTS idx_role_permissions_permission_id ON role_permissions(permission_id)`,

		// Audit logs table
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
			success BOOLEAN NOT NULL DEFAULT TRUE,
			error_code VARCHAR(255),
			error_message TEXT,
			metadata JSONB DEFAULT '{}',
			created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_id ON audit_logs(tenant_id)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_resource ON audit_logs(resource)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_success ON audit_logs(success)`,

		// Email templates table
		`CREATE TABLE IF NOT EXISTS email_templates (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL,
			name VARCHAR(255) NOT NULL,
			subject VARCHAR(500) NOT NULL,
			body_html TEXT,
			body_text TEXT,
			variables JSONB DEFAULT '[]',
			is_active BOOLEAN NOT NULL DEFAULT TRUE,
			created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			deleted_at TIMESTAMP WITH TIME ZONE
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_email_templates_tenant_name ON email_templates(tenant_id, name) WHERE deleted_at IS NULL`,
		`CREATE INDEX IF NOT EXISTS idx_email_templates_tenant_id ON email_templates(tenant_id)`,

		// Email queue table
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
			created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_email_queue_tenant_id ON email_queue(tenant_id)`,
		`CREATE INDEX IF NOT EXISTS idx_email_queue_status ON email_queue(status)`,
		`CREATE INDEX IF NOT EXISTS idx_email_queue_priority ON email_queue(priority)`,
		`CREATE INDEX IF NOT EXISTS idx_email_queue_scheduled_at ON email_queue(scheduled_at)`,

		// Email verifications table
		`CREATE TABLE IF NOT EXISTS email_verifications (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL,
			user_id UUID NOT NULL,
			email VARCHAR(255) NOT NULL,
			code VARCHAR(255) NOT NULL UNIQUE,
			expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
			verified_at TIMESTAMP WITH TIME ZONE,
			created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_email_verifications_tenant_id ON email_verifications(tenant_id)`,
		`CREATE INDEX IF NOT EXISTS idx_email_verifications_user_id ON email_verifications(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_email_verifications_expires_at ON email_verifications(expires_at)`,

		// Password resets table
		`CREATE TABLE IF NOT EXISTS password_resets (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL,
			user_id UUID NOT NULL,
			token VARCHAR(255) NOT NULL UNIQUE,
			expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
			used_at TIMESTAMP WITH TIME ZONE,
			created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_password_resets_tenant_id ON password_resets(tenant_id)`,
		`CREATE INDEX IF NOT EXISTS idx_password_resets_user_id ON password_resets(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_password_resets_expires_at ON password_resets(expires_at)`,
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
