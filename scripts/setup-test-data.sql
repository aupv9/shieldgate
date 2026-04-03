-- Setup test data for OAuth login testing
-- This script creates a test tenant, user, and OAuth client

-- Insert test tenant
INSERT INTO tenants (id, name, domain, is_active, created_at, updated_at) 
VALUES (
    '550e8400-e29b-41d4-a716-446655440000',
    'Test Tenant',
    'test.example.com',
    true,
    NOW(),
    NOW()
) ON CONFLICT (id) DO NOTHING;

-- Insert test user (password: "password123")
INSERT INTO users (id, tenant_id, username, email, password_hash, created_at, updated_at)
VALUES (
    '550e8400-e29b-41d4-a716-446655440001',
    '550e8400-e29b-41d4-a716-446655440000',
    'testuser',
    'test@example.com',
    '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj/hL.ckstG.',  -- bcrypt hash of "password123"
    NOW(),
    NOW()
) ON CONFLICT (id) DO NOTHING;

-- Insert test OAuth client (public client for testing)
INSERT INTO clients (id, tenant_id, client_id, name, redirect_uris, grant_types, scopes, is_public, created_at, updated_at)
VALUES (
    '550e8400-e29b-41d4-a716-446655440002',
    '550e8400-e29b-41d4-a716-446655440000',
    'test-client-123',
    'Test OAuth Client',
    '["http://localhost:3000/callback", "http://localhost:8080/callback"]',
    '["authorization_code", "refresh_token"]',
    '["read", "write", "openid", "profile", "email"]',
    true,
    NOW(),
    NOW()
) ON CONFLICT (id) DO NOTHING;

-- Verify data was inserted
SELECT 'Tenants:' as table_name, count(*) as count FROM tenants WHERE id = '550e8400-e29b-41d4-a716-446655440000'
UNION ALL
SELECT 'Users:', count(*) FROM users WHERE tenant_id = '550e8400-e29b-41d4-a716-446655440000'
UNION ALL
SELECT 'Clients:', count(*) FROM clients WHERE tenant_id = '550e8400-e29b-41d4-a716-446655440000';