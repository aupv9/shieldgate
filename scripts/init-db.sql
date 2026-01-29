-- ShieldGate Database Initialization Script
-- This script sets up the initial database structure and configuration

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Set timezone
SET timezone = 'UTC';

-- Create custom types for better data integrity
DO $$ BEGIN
    CREATE TYPE grant_type AS ENUM ('authorization_code', 'refresh_token', 'client_credentials', 'implicit');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Create tenants table
CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    domain VARCHAR(255) UNIQUE NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE
);

-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    username VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE,
    
    -- Ensure unique username and email per tenant
    CONSTRAINT unique_username_per_tenant UNIQUE (tenant_id, username),
    CONSTRAINT unique_email_per_tenant UNIQUE (tenant_id, email)
);

-- Create clients table
CREATE TABLE IF NOT EXISTS clients (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id VARCHAR(255) NOT NULL,
    client_secret VARCHAR(255),
    name VARCHAR(255) NOT NULL,
    redirect_uris JSONB NOT NULL DEFAULT '[]',
    grant_types JSONB NOT NULL DEFAULT '[]',
    scopes JSONB NOT NULL DEFAULT '[]',
    is_public BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE,
    
    -- Ensure unique client_id per tenant
    CONSTRAINT unique_client_id_per_tenant UNIQUE (tenant_id, client_id)
);

-- Create authorization_codes table
CREATE TABLE IF NOT EXISTS authorization_codes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    code VARCHAR(255) NOT NULL,
    client_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    redirect_uri VARCHAR(255) NOT NULL,
    scope TEXT,
    code_challenge VARCHAR(255),
    code_challenge_method VARCHAR(50),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- Ensure unique code per tenant
    CONSTRAINT unique_code_per_tenant UNIQUE (tenant_id, code)
);

-- Create access_tokens table
CREATE TABLE IF NOT EXISTS access_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    token VARCHAR(255) NOT NULL,
    client_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scope TEXT,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- Ensure unique token per tenant
    CONSTRAINT unique_token_per_tenant UNIQUE (tenant_id, token)
);

-- Create refresh_tokens table
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    token VARCHAR(255) NOT NULL,
    client_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- Ensure unique token per tenant
    CONSTRAINT unique_refresh_token_per_tenant UNIQUE (tenant_id, token)
);

-- Create updated_at trigger function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers for updated_at
CREATE TRIGGER update_tenants_updated_at BEFORE UPDATE ON tenants FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_clients_updated_at BEFORE UPDATE ON clients FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Insert default tenant for development
INSERT INTO tenants (id, name, domain, is_active) 
VALUES (
    '00000000-0000-0000-0000-000000000001',
    'Default Tenant',
    'localhost',
    true
) ON CONFLICT (domain) DO NOTHING;

-- Insert default admin user for development
INSERT INTO users (id, tenant_id, username, email, password_hash) 
VALUES (
    '00000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000001',
    'admin',
    'admin@localhost',
    '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj3QJgusgm2G' -- password: admin123
) ON CONFLICT (tenant_id, email) DO NOTHING;

-- Insert default OAuth client for development
INSERT INTO clients (id, tenant_id, client_id, client_secret, name, redirect_uris, grant_types, scopes, is_public) 
VALUES (
    '00000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000001',
    'shieldgate-dev-client',
    'dev-client-secret-change-in-production',
    'ShieldGate Development Client',
    '["http://localhost:3000/callback", "http://localhost:8080/callback"]',
    '["authorization_code", "refresh_token", "client_credentials"]',
    '["read", "write", "openid", "profile", "email"]',
    false
) ON CONFLICT (tenant_id, client_id) DO NOTHING;

-- Insert public client for SPA applications
INSERT INTO clients (id, tenant_id, client_id, name, redirect_uris, grant_types, scopes, is_public) 
VALUES (
    '00000000-0000-0000-0000-000000000002',
    '00000000-0000-0000-0000-000000000001',
    'shieldgate-spa-client',
    'ShieldGate SPA Client',
    '["http://localhost:3000/callback", "http://localhost:8080/callback"]',
    '["authorization_code", "refresh_token"]',
    '["read", "write", "openid", "profile", "email"]',
    true
) ON CONFLICT (tenant_id, client_id) DO NOTHING;