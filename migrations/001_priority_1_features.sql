-- Migration: Priority 1 Features - RBAC, Audit Logging, Email System, Enhanced User Management
-- Created: 2025-01-29

-- =====================================================
-- ENHANCED USER MANAGEMENT
-- =====================================================

-- Add new columns to users table for enhanced user management
ALTER TABLE users ADD COLUMN IF NOT EXISTS status VARCHAR(20) NOT NULL DEFAULT 'pending';
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verification_code VARCHAR(255);
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verification_expires_at TIMESTAMP;
ALTER TABLE users ADD COLUMN IF NOT EXISTS phone_number VARCHAR(50);
ALTER TABLE users ADD COLUMN IF NOT EXISTS phone_verified BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS first_name VARCHAR(255);
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_name VARCHAR(255);
ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar VARCHAR(500);
ALTER TABLE users ADD COLUMN IF NOT EXISTS locale VARCHAR(10) DEFAULT 'en';
ALTER TABLE users ADD COLUMN IF NOT EXISTS timezone VARCHAR(50) DEFAULT 'UTC';
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMP;
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_ip VARCHAR(45);
ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_login_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_at TIMESTAMP;
ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMP;
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_reset_token VARCHAR(255);
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_reset_expires_at TIMESTAMP;
ALTER TABLE users ADD COLUMN IF NOT EXISTS metadata JSONB DEFAULT '{}';

-- Add indexes for enhanced user management
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);
CREATE INDEX IF NOT EXISTS idx_users_email_verified ON users(email_verified);
CREATE INDEX IF NOT EXISTS idx_users_last_login_at ON users(last_login_at);

-- =====================================================
-- RBAC SYSTEM
-- =====================================================

-- Permissions table
CREATE TABLE IF NOT EXISTS permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL UNIQUE,
    display_name VARCHAR(255) NOT NULL,
    description TEXT,
    resource VARCHAR(255) NOT NULL,
    action VARCHAR(255) NOT NULL,
    is_system BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMP
);

-- Roles table
CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    name VARCHAR(255) NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    description TEXT,
    is_system BOOLEAN NOT NULL DEFAULT FALSE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMP,
    
    CONSTRAINT fk_roles_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

-- User roles junction table
CREATE TABLE IF NOT EXISTS user_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    user_id UUID NOT NULL,
    role_id UUID NOT NULL,
    granted_by UUID NOT NULL,
    granted_at TIMESTAMP NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP,
    
    CONSTRAINT fk_user_roles_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    CONSTRAINT fk_user_roles_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_user_roles_role FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    CONSTRAINT fk_user_roles_granted_by FOREIGN KEY (granted_by) REFERENCES users(id)
);

-- Role permissions junction table
CREATE TABLE IF NOT EXISTS role_permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role_id UUID NOT NULL,
    permission_id UUID NOT NULL,
    granted_by UUID NOT NULL,
    granted_at TIMESTAMP NOT NULL DEFAULT NOW(),
    
    CONSTRAINT fk_role_permissions_role FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    CONSTRAINT fk_role_permissions_permission FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE,
    CONSTRAINT fk_role_permissions_granted_by FOREIGN KEY (granted_by) REFERENCES users(id)
);

-- RBAC Indexes
CREATE INDEX IF NOT EXISTS idx_permissions_name ON permissions(name);
CREATE INDEX IF NOT EXISTS idx_permissions_resource ON permissions(resource);
CREATE INDEX IF NOT EXISTS idx_permissions_action ON permissions(action);
CREATE INDEX IF NOT EXISTS idx_permissions_deleted_at ON permissions(deleted_at);

CREATE UNIQUE INDEX IF NOT EXISTS idx_roles_tenant_name ON roles(tenant_id, name) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_roles_tenant_id ON roles(tenant_id);
CREATE INDEX IF NOT EXISTS idx_roles_is_active ON roles(is_active);
CREATE INDEX IF NOT EXISTS idx_roles_deleted_at ON roles(deleted_at);

CREATE INDEX IF NOT EXISTS idx_user_roles_tenant_id ON user_roles(tenant_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role_id ON user_roles(role_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_expires_at ON user_roles(expires_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_user_roles_unique ON user_roles(tenant_id, user_id, role_id);

CREATE INDEX IF NOT EXISTS idx_role_permissions_role_id ON role_permissions(role_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_permission_id ON role_permissions(permission_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_role_permissions_unique ON role_permissions(role_id, permission_id);

-- =====================================================
-- AUDIT LOGGING SYSTEM
-- =====================================================

-- Audit logs table
CREATE TABLE IF NOT EXISTS audit_logs (
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
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    
    CONSTRAINT fk_audit_logs_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    CONSTRAINT fk_audit_logs_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT fk_audit_logs_client FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE SET NULL
);

-- Audit logs indexes
CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_id ON audit_logs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_client_id ON audit_logs(client_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_resource ON audit_logs(resource);
CREATE INDEX IF NOT EXISTS idx_audit_logs_resource_id ON audit_logs(resource_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_ip ON audit_logs(ip_address);
CREATE INDEX IF NOT EXISTS idx_audit_logs_request_id ON audit_logs(request_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_success ON audit_logs(success);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);

-- Composite indexes for common queries
CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_user ON audit_logs(tenant_id, user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_resource ON audit_logs(tenant_id, resource, resource_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_action ON audit_logs(tenant_id, action, created_at DESC);

-- =====================================================
-- EMAIL SYSTEM
-- =====================================================

-- Email templates table
CREATE TABLE IF NOT EXISTS email_templates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    name VARCHAR(255) NOT NULL,
    subject VARCHAR(500) NOT NULL,
    body_html TEXT,
    body_text TEXT,
    variables JSONB DEFAULT '[]',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMP,
    
    CONSTRAINT fk_email_templates_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

-- Email queue table
CREATE TABLE IF NOT EXISTS email_queue (
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
    scheduled_at TIMESTAMP NOT NULL DEFAULT NOW(),
    sent_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    
    CONSTRAINT fk_email_queue_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    CONSTRAINT fk_email_queue_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Email verification table
CREATE TABLE IF NOT EXISTS email_verifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    user_id UUID NOT NULL,
    email VARCHAR(255) NOT NULL,
    code VARCHAR(255) NOT NULL UNIQUE,
    expires_at TIMESTAMP NOT NULL,
    verified_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    
    CONSTRAINT fk_email_verifications_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    CONSTRAINT fk_email_verifications_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Password reset table
CREATE TABLE IF NOT EXISTS password_resets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    user_id UUID NOT NULL,
    token VARCHAR(255) NOT NULL UNIQUE,
    expires_at TIMESTAMP NOT NULL,
    used_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    
    CONSTRAINT fk_password_resets_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    CONSTRAINT fk_password_resets_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Email system indexes
CREATE UNIQUE INDEX IF NOT EXISTS idx_email_templates_tenant_name ON email_templates(tenant_id, name) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_email_templates_tenant_id ON email_templates(tenant_id);
CREATE INDEX IF NOT EXISTS idx_email_templates_deleted_at ON email_templates(deleted_at);

CREATE INDEX IF NOT EXISTS idx_email_queue_tenant_id ON email_queue(tenant_id);
CREATE INDEX IF NOT EXISTS idx_email_queue_user_id ON email_queue(user_id);
CREATE INDEX IF NOT EXISTS idx_email_queue_to_email ON email_queue(to_email);
CREATE INDEX IF NOT EXISTS idx_email_queue_status ON email_queue(status);
CREATE INDEX IF NOT EXISTS idx_email_queue_priority ON email_queue(priority);
CREATE INDEX IF NOT EXISTS idx_email_queue_scheduled_at ON email_queue(scheduled_at);

CREATE INDEX IF NOT EXISTS idx_email_verifications_tenant_id ON email_verifications(tenant_id);
CREATE INDEX IF NOT EXISTS idx_email_verifications_user_id ON email_verifications(user_id);
CREATE INDEX IF NOT EXISTS idx_email_verifications_code ON email_verifications(code);
CREATE INDEX IF NOT EXISTS idx_email_verifications_expires_at ON email_verifications(expires_at);

CREATE INDEX IF NOT EXISTS idx_password_resets_tenant_id ON password_resets(tenant_id);
CREATE INDEX IF NOT EXISTS idx_password_resets_user_id ON password_resets(user_id);
CREATE INDEX IF NOT EXISTS idx_password_resets_token ON password_resets(token);
CREATE INDEX IF NOT EXISTS idx_password_resets_expires_at ON password_resets(expires_at);

-- =====================================================
-- DEFAULT PERMISSIONS
-- =====================================================

-- Insert default system permissions
INSERT INTO permissions (name, display_name, description, resource, action, is_system) VALUES
-- User management permissions
('users.create', 'Create Users', 'Create new users', 'user', 'create', true),
('users.read', 'Read Users', 'View user information', 'user', 'read', true),
('users.update', 'Update Users', 'Update user information', 'user', 'update', true),
('users.delete', 'Delete Users', 'Delete users', 'user', 'delete', true),
('users.manage', 'Manage Users', 'Full user management access', 'user', 'manage', true),

-- Client management permissions
('clients.create', 'Create Clients', 'Create OAuth clients', 'client', 'create', true),
('clients.read', 'Read Clients', 'View OAuth clients', 'client', 'read', true),
('clients.update', 'Update Clients', 'Update OAuth clients', 'client', 'update', true),
('clients.delete', 'Delete Clients', 'Delete OAuth clients', 'client', 'delete', true),
('clients.manage', 'Manage Clients', 'Full client management access', 'client', 'manage', true),

-- Role management permissions
('roles.create', 'Create Roles', 'Create new roles', 'role', 'create', true),
('roles.read', 'Read Roles', 'View roles', 'role', 'read', true),
('roles.update', 'Update Roles', 'Update roles', 'role', 'update', true),
('roles.delete', 'Delete Roles', 'Delete roles', 'role', 'delete', true),
('roles.assign', 'Assign Roles', 'Assign roles to users', 'role', 'assign', true),
('roles.manage', 'Manage Roles', 'Full role management access', 'role', 'manage', true),

-- Permission management permissions
('permissions.create', 'Create Permissions', 'Create new permissions', 'permission', 'create', true),
('permissions.read', 'Read Permissions', 'View permissions', 'permission', 'read', true),
('permissions.update', 'Update Permissions', 'Update permissions', 'permission', 'update', true),
('permissions.delete', 'Delete Permissions', 'Delete permissions', 'permission', 'delete', true),
('permissions.manage', 'Manage Permissions', 'Full permission management access', 'permission', 'manage', true),

-- Audit log permissions
('audit.read', 'Read Audit Logs', 'View audit logs', 'audit', 'read', true),
('audit.export', 'Export Audit Logs', 'Export audit logs', 'audit', 'export', true),
('audit.manage', 'Manage Audit Logs', 'Full audit log access', 'audit', 'manage', true),

-- Email management permissions
('emails.send', 'Send Emails', 'Send emails', 'email', 'send', true),
('emails.templates.create', 'Create Email Templates', 'Create email templates', 'email_template', 'create', true),
('emails.templates.read', 'Read Email Templates', 'View email templates', 'email_template', 'read', true),
('emails.templates.update', 'Update Email Templates', 'Update email templates', 'email_template', 'update', true),
('emails.templates.delete', 'Delete Email Templates', 'Delete email templates', 'email_template', 'delete', true),
('emails.queue.read', 'Read Email Queue', 'View email queue', 'email_queue', 'read', true),
('emails.queue.manage', 'Manage Email Queue', 'Manage email queue', 'email_queue', 'manage', true),

-- Tenant management permissions
('tenants.create', 'Create Tenants', 'Create new tenants', 'tenant', 'create', true),
('tenants.read', 'Read Tenants', 'View tenant information', 'tenant', 'read', true),
('tenants.update', 'Update Tenants', 'Update tenant information', 'tenant', 'update', true),
('tenants.delete', 'Delete Tenants', 'Delete tenants', 'tenant', 'delete', true),
('tenants.manage', 'Manage Tenants', 'Full tenant management access', 'tenant', 'manage', true)

ON CONFLICT (name) DO NOTHING;

-- =====================================================
-- CLEANUP FUNCTIONS
-- =====================================================

-- Function to cleanup expired tokens and codes
CREATE OR REPLACE FUNCTION cleanup_expired_data()
RETURNS void AS $$
BEGIN
    -- Cleanup expired authorization codes
    DELETE FROM authorization_codes WHERE expires_at < NOW();
    
    -- Cleanup expired access tokens
    DELETE FROM access_tokens WHERE expires_at < NOW();
    
    -- Cleanup expired refresh tokens
    DELETE FROM refresh_tokens WHERE expires_at < NOW();
    
    -- Cleanup expired email verifications
    DELETE FROM email_verifications WHERE expires_at < NOW() AND verified_at IS NULL;
    
    -- Cleanup expired password resets
    DELETE FROM password_resets WHERE expires_at < NOW() AND used_at IS NULL;
    
    -- Cleanup old audit logs (older than 1 year)
    DELETE FROM audit_logs WHERE created_at < NOW() - INTERVAL '1 year';
    
    -- Cleanup sent emails older than 30 days
    DELETE FROM email_queue WHERE status = 'sent' AND sent_at < NOW() - INTERVAL '30 days';
    
    -- Cleanup failed emails with max attempts reached older than 7 days
    DELETE FROM email_queue WHERE status = 'failed' AND attempts >= max_attempts AND created_at < NOW() - INTERVAL '7 days';
END;
$$ LANGUAGE plpgsql;

-- =====================================================
-- TRIGGERS
-- =====================================================

-- Update updated_at timestamp trigger function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Add updated_at triggers for new tables
CREATE TRIGGER update_roles_updated_at BEFORE UPDATE ON roles FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_email_templates_updated_at BEFORE UPDATE ON email_templates FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_email_queue_updated_at BEFORE UPDATE ON email_queue FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- =====================================================
-- COMMENTS
-- =====================================================

COMMENT ON TABLE permissions IS 'System permissions for RBAC';
COMMENT ON TABLE roles IS 'Tenant-specific roles';
COMMENT ON TABLE user_roles IS 'User role assignments';
COMMENT ON TABLE role_permissions IS 'Role permission assignments';
COMMENT ON TABLE audit_logs IS 'Audit trail for all system actions';
COMMENT ON TABLE email_templates IS 'Email templates for notifications';
COMMENT ON TABLE email_queue IS 'Email sending queue';
COMMENT ON TABLE email_verifications IS 'Email verification codes';
COMMENT ON TABLE password_resets IS 'Password reset tokens';

COMMENT ON FUNCTION cleanup_expired_data() IS 'Cleanup expired tokens, codes, and old audit logs';
COMMENT ON FUNCTION update_updated_at_column() IS 'Automatically update updated_at timestamp';