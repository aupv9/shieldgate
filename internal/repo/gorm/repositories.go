package gorm

import (
	"shieldgate/internal/repo"

	"gorm.io/gorm"
)

// NewRepositories creates a new repositories instance with GORM implementations
func NewRepositories(db *gorm.DB) *repo.Repositories {
	return &repo.Repositories{
		Tenant:         NewTenantRepository(db),
		User:           NewUserRepository(db),
		Client:         NewClientRepository(db),
		AuthCode:       NewAuthCodeRepository(db),
		AccessToken:    NewAccessTokenRepository(db),
		RefreshToken:   NewRefreshTokenRepository(db),
		Role:           NewRoleRepository(db),
		Permission:     NewPermissionRepository(db),
		UserRole:       NewUserRoleRepository(db),
		RolePermission: NewRolePermissionRepository(db),
	}
}
