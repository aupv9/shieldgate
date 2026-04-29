package database

import (
	"fmt"

	"github.com/sirupsen/logrus"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Initialize opens a GORM/Postgres connection and configures the pool.
func Initialize(databaseURL string) (*gorm.DB, error) {
	logrus.Info("Connecting to database...")
	gormLogger := logger.Default.LogMode(logger.Info)
	db, err := gorm.Open(postgres.Open(databaseURL), &gorm.Config{
		Logger:                                   gormLogger,
		DisableForeignKeyConstraintWhenMigrating: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open database connection: %w", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get underlying sql.DB: %w", err)
	}
	sqlDB.SetMaxOpenConns(25)
	sqlDB.SetMaxIdleConns(5)
	logrus.Info("Database connection established")
	return db, nil
}

// Migrate runs all DDL migrations in order.
func Migrate(db *gorm.DB) error {
	logrus.Info("Running database migrations...")

	migrations := []string{
		// ── tenants ─────────────────────────────────────────────────────────
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

		// ── users ────────────────────────────────────────────────────────────
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

		// ── clients ──────────────────────────────────────────────────────────
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

		// ── authorization_codes ───────────────────────────────────────────────
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
		`CREATE INDEX IF NOT EXISTS idx_authorization_codes_expires_at ON authorization_codes(expires_at)`,

		// ── access_tokens ─────────────────────────────────────────────────────
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
		`CREATE INDEX IF NOT EXISTS idx_access_tokens_expires_at ON access_tokens(expires_at)`,

		// ── refresh_tokens ────────────────────────────────────────────────────
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
		`CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at ON refresh_tokens(expires_at)`,

		// ── mfa_secrets (Phase 5) ─────────────────────────────────────────────
		`CREATE TABLE IF NOT EXISTS mfa_secrets (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL,
			user_id UUID NOT NULL,
			secret VARCHAR(255) NOT NULL,
			algorithm VARCHAR(20) NOT NULL DEFAULT 'SHA1',
			digits INTEGER NOT NULL DEFAULT 6,
			period INTEGER NOT NULL DEFAULT 30,
			enabled BOOLEAN NOT NULL DEFAULT false,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_mfa_secrets_tenant ON mfa_secrets(tenant_id)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_mfa_secrets_user_tenant ON mfa_secrets(user_id, tenant_id)`,

		// ── mfa_backup_codes (Phase 5) ────────────────────────────────────────
		`CREATE TABLE IF NOT EXISTS mfa_backup_codes (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL,
			user_id UUID NOT NULL,
			code_hash VARCHAR(255) NOT NULL,
			used_at TIMESTAMP WITH TIME ZONE,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_mfa_backup_codes_user ON mfa_backup_codes(user_id)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_mfa_backup_codes_hash ON mfa_backup_codes(code_hash)`,

		// ── sessions (Phase 5) ────────────────────────────────────────────────
		`CREATE TABLE IF NOT EXISTS sessions (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL,
			user_id UUID NOT NULL,
			token_id VARCHAR(255) NOT NULL,
			ip_address VARCHAR(45),
			user_agent TEXT,
			device_name VARCHAR(255),
			last_active_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
			revoked_at TIMESTAMP WITH TIME ZONE,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			deleted_at TIMESTAMP WITH TIME ZONE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_tenant ON sessions(tenant_id)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_sessions_token_id ON sessions(token_id) WHERE deleted_at IS NULL`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)`,

		// ── login_attempts (Phase 5) ──────────────────────────────────────────
		`CREATE TABLE IF NOT EXISTS login_attempts (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL,
			user_id UUID,
			ip_address VARCHAR(45) NOT NULL,
			email VARCHAR(255) NOT NULL,
			success BOOLEAN NOT NULL,
			fail_reason VARCHAR(255),
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_login_attempts_ip ON login_attempts(ip_address)`,
		`CREATE INDEX IF NOT EXISTS idx_login_attempts_email ON login_attempts(email)`,
		`CREATE INDEX IF NOT EXISTS idx_login_attempts_created ON login_attempts(created_at)`,

		// ── social_providers (Phase 7) ────────────────────────────────────────
		`CREATE TABLE IF NOT EXISTS social_providers (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL,
			provider VARCHAR(50) NOT NULL,
			client_id VARCHAR(255) NOT NULL,
			client_secret VARCHAR(255) NOT NULL,
			scopes JSONB NOT NULL DEFAULT '[]',
			is_active BOOLEAN NOT NULL DEFAULT true,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			deleted_at TIMESTAMP WITH TIME ZONE
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_social_providers_tenant_provider ON social_providers(tenant_id, provider) WHERE deleted_at IS NULL`,
		`CREATE INDEX IF NOT EXISTS idx_social_providers_tenant ON social_providers(tenant_id)`,

		// ── social_accounts (Phase 7) ─────────────────────────────────────────
		`CREATE TABLE IF NOT EXISTS social_accounts (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL,
			user_id UUID NOT NULL,
			provider VARCHAR(50) NOT NULL,
			external_id VARCHAR(255) NOT NULL,
			email VARCHAR(255),
			name VARCHAR(255),
			avatar VARCHAR(500),
			access_token TEXT,
			refresh_token TEXT,
			token_expires_at TIMESTAMP WITH TIME ZONE,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_social_accounts_provider_external ON social_accounts(provider, external_id)`,
		`CREATE INDEX IF NOT EXISTS idx_social_accounts_user ON social_accounts(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_social_accounts_tenant ON social_accounts(tenant_id)`,

		// ── webhook_endpoints (Phase 7) ───────────────────────────────────────
		`CREATE TABLE IF NOT EXISTS webhook_endpoints (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL,
			url VARCHAR(500) NOT NULL,
			secret VARCHAR(255) NOT NULL,
			events JSONB NOT NULL DEFAULT '[]',
			is_active BOOLEAN NOT NULL DEFAULT true,
			description VARCHAR(500),
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			deleted_at TIMESTAMP WITH TIME ZONE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_webhooks_tenant_id ON webhook_endpoints(tenant_id)`,

		// ── webhook_deliveries (Phase 7) ──────────────────────────────────────
		`CREATE TABLE IF NOT EXISTS webhook_deliveries (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			webhook_id UUID NOT NULL,
			tenant_id UUID NOT NULL,
			event VARCHAR(255) NOT NULL,
			payload TEXT,
			status_code INTEGER,
			response_body TEXT,
			attempt INTEGER NOT NULL DEFAULT 1,
			success BOOLEAN NOT NULL DEFAULT false,
			error_message TEXT,
			delivered_at TIMESTAMP WITH TIME ZONE,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_webhook_id ON webhook_deliveries(webhook_id)`,
		`CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_tenant ON webhook_deliveries(tenant_id)`,
		`CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_event ON webhook_deliveries(event)`,
		`CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_created ON webhook_deliveries(created_at)`,

		// ── api_keys (Phase 7) ────────────────────────────────────────────────
		`CREATE TABLE IF NOT EXISTS api_keys (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL,
			user_id UUID,
			name VARCHAR(255) NOT NULL,
			key_hash VARCHAR(255) NOT NULL,
			last_four VARCHAR(4) NOT NULL,
			prefix VARCHAR(10) NOT NULL,
			scopes JSONB NOT NULL DEFAULT '[]',
			expires_at TIMESTAMP WITH TIME ZONE,
			last_used_at TIMESTAMP WITH TIME ZONE,
			revoked_at TIMESTAMP WITH TIME ZONE,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			deleted_at TIMESTAMP WITH TIME ZONE
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash) WHERE deleted_at IS NULL`,
		`CREATE INDEX IF NOT EXISTS idx_api_keys_tenant_id ON api_keys(tenant_id)`,
		`CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id)`,

		// ── consent_records (Phase 16) ────────────────────────────────────────
		`CREATE TABLE IF NOT EXISTS consent_records (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL,
			user_id UUID NOT NULL,
			client_id UUID NOT NULL,
			scopes JSONB NOT NULL DEFAULT '[]',
			expires_at TIMESTAMP WITH TIME ZONE,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			deleted_at TIMESTAMP WITH TIME ZONE
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_consent_records_tenant_user_client ON consent_records(tenant_id, user_id, client_id) WHERE deleted_at IS NULL`,
		`CREATE INDEX IF NOT EXISTS idx_consent_records_user ON consent_records(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_consent_records_tenant ON consent_records(tenant_id)`,

		// ── token_blocklist (Phase 16) ────────────────────────────────────────
		`CREATE TABLE IF NOT EXISTS token_blocklists (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			jti VARCHAR(255) NOT NULL,
			tenant_id UUID NOT NULL,
			user_id UUID,
			expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_blocklist_jti ON token_blocklists(jti)`,
		`CREATE INDEX IF NOT EXISTS idx_blocklist_tenant ON token_blocklists(tenant_id)`,
		`CREATE INDEX IF NOT EXISTS idx_blocklist_expires ON token_blocklists(expires_at)`,
	}

	for i, m := range migrations {
		logrus.Infof("Executing migration %d/%d", i+1, len(migrations))
		if err := db.Exec(m).Error; err != nil {
			return fmt.Errorf("failed to execute migration %d: %w", i+1, err)
		}
	}

	logrus.Info("Database migrations completed successfully")
	return nil
}
