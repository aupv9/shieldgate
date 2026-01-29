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
