-- ShieldGate Database Indexes for Performance Optimization
-- This script creates indexes for optimal query performance

-- Tenants table indexes
CREATE INDEX IF NOT EXISTS idx_tenants_domain ON tenants(domain) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_tenants_active ON tenants(is_active) WHERE deleted_at IS NULL;

-- Users table indexes
CREATE INDEX IF NOT EXISTS idx_users_tenant_id ON users(tenant_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_users_tenant_username ON users(tenant_id, username) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_users_tenant_email ON users(tenant_id, email) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at) WHERE deleted_at IS NULL;

-- Clients table indexes
CREATE INDEX IF NOT EXISTS idx_clients_tenant_id ON clients(tenant_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_clients_tenant_client_id ON clients(tenant_id, client_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_clients_client_id ON clients(client_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_clients_is_public ON clients(is_public) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_clients_created_at ON clients(created_at) WHERE deleted_at IS NULL;

-- Authorization codes table indexes
CREATE INDEX IF NOT EXISTS idx_auth_codes_tenant_id ON authorization_codes(tenant_id);
CREATE INDEX IF NOT EXISTS idx_auth_codes_tenant_code ON authorization_codes(tenant_id, code);
CREATE INDEX IF NOT EXISTS idx_auth_codes_code ON authorization_codes(code);
CREATE INDEX IF NOT EXISTS idx_auth_codes_client_id ON authorization_codes(client_id);
CREATE INDEX IF NOT EXISTS idx_auth_codes_user_id ON authorization_codes(user_id);
CREATE INDEX IF NOT EXISTS idx_auth_codes_expires_at ON authorization_codes(expires_at);
CREATE INDEX IF NOT EXISTS idx_auth_codes_created_at ON authorization_codes(created_at);

-- Access tokens table indexes
CREATE INDEX IF NOT EXISTS idx_access_tokens_tenant_id ON access_tokens(tenant_id);
CREATE INDEX IF NOT EXISTS idx_access_tokens_tenant_token ON access_tokens(tenant_id, token);
CREATE INDEX IF NOT EXISTS idx_access_tokens_token ON access_tokens(token);
CREATE INDEX IF NOT EXISTS idx_access_tokens_client_id ON access_tokens(client_id);
CREATE INDEX IF NOT EXISTS idx_access_tokens_user_id ON access_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_access_tokens_expires_at ON access_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_access_tokens_created_at ON access_tokens(created_at);

-- Refresh tokens table indexes
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_tenant_id ON refresh_tokens(tenant_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_tenant_token ON refresh_tokens(tenant_id, token);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token ON refresh_tokens(token);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_client_id ON refresh_tokens(client_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_created_at ON refresh_tokens(created_at);

-- Composite indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_users_tenant_email_active ON users(tenant_id, email) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_clients_tenant_active ON clients(tenant_id, is_public) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_auth_codes_client_user ON authorization_codes(client_id, user_id);
CREATE INDEX IF NOT EXISTS idx_access_tokens_client_user ON access_tokens(client_id, user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_client_user ON refresh_tokens(client_id, user_id);

-- Partial indexes for expired token cleanup
CREATE INDEX IF NOT EXISTS idx_auth_codes_expired ON authorization_codes(expires_at) WHERE expires_at < CURRENT_TIMESTAMP;
CREATE INDEX IF NOT EXISTS idx_access_tokens_expired ON access_tokens(expires_at) WHERE expires_at < CURRENT_TIMESTAMP;
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expired ON refresh_tokens(expires_at) WHERE expires_at < CURRENT_TIMESTAMP;

-- JSONB indexes for client configuration
CREATE INDEX IF NOT EXISTS idx_clients_redirect_uris ON clients USING GIN (redirect_uris);
CREATE INDEX IF NOT EXISTS idx_clients_grant_types ON clients USING GIN (grant_types);
CREATE INDEX IF NOT EXISTS idx_clients_scopes ON clients USING GIN (scopes);

-- Statistics update for better query planning
ANALYZE tenants;
ANALYZE users;
ANALYZE clients;
ANALYZE authorization_codes;
ANALYZE access_tokens;
ANALYZE refresh_tokens;