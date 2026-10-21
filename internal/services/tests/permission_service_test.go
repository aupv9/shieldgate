package tests

// permission_service_test.go covers effective-permission resolution through
// user roles: expiry, inactive roles, de-duplication, and permission deletion.

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"shieldgate/internal/models"
	"shieldgate/internal/services"
)

// --- in-memory RBAC repositories ---

type fakeRoleRepo struct{ roles map[uuid.UUID]*models.Role }

func (r *fakeRoleRepo) Create(ctx context.Context, role *models.Role) error {
	r.roles[role.ID] = role
	return nil
}
func (r *fakeRoleRepo) GetByID(ctx context.Context, tenantID, roleID uuid.UUID) (*models.Role, error) {
	if role, ok := r.roles[roleID]; ok && role.TenantID == tenantID {
		return role, nil
	}
	return nil, models.ErrRoleNotFound
}
func (r *fakeRoleRepo) GetByName(ctx context.Context, tenantID uuid.UUID, name string) (*models.Role, error) {
	return nil, models.ErrRoleNotFound
}
func (r *fakeRoleRepo) Update(ctx context.Context, role *models.Role) error          { return nil }
func (r *fakeRoleRepo) Delete(ctx context.Context, tenantID, roleID uuid.UUID) error { return nil }
func (r *fakeRoleRepo) List(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]*models.Role, int64, error) {
	return nil, 0, nil
}
func (r *fakeRoleRepo) GetWithPermissions(ctx context.Context, tenantID, roleID uuid.UUID) (*models.Role, error) {
	return r.GetByID(ctx, tenantID, roleID)
}

type fakePermissionRepo struct {
	permissions map[uuid.UUID]*models.Permission
}

func (r *fakePermissionRepo) Create(ctx context.Context, p *models.Permission) error {
	r.permissions[p.ID] = p
	return nil
}
func (r *fakePermissionRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.Permission, error) {
	if p, ok := r.permissions[id]; ok {
		return p, nil
	}
	return nil, models.ErrPermissionNotFound
}
func (r *fakePermissionRepo) GetByName(ctx context.Context, name string) (*models.Permission, error) {
	for _, p := range r.permissions {
		if p.Name == name {
			return p, nil
		}
	}
	return nil, models.ErrPermissionNotFound
}
func (r *fakePermissionRepo) Update(ctx context.Context, p *models.Permission) error { return nil }
func (r *fakePermissionRepo) Delete(ctx context.Context, id uuid.UUID) error {
	delete(r.permissions, id)
	return nil
}
func (r *fakePermissionRepo) List(ctx context.Context, limit, offset int) ([]*models.Permission, int64, error) {
	return nil, 0, nil
}
func (r *fakePermissionRepo) GetByResource(ctx context.Context, resource string) ([]*models.Permission, error) {
	return nil, nil
}

type fakeUserRoleRepo struct{ userRoles []*models.UserRole }

func (r *fakeUserRoleRepo) Create(ctx context.Context, ur *models.UserRole) error {
	r.userRoles = append(r.userRoles, ur)
	return nil
}
func (r *fakeUserRoleRepo) GetByID(ctx context.Context, tenantID, id uuid.UUID) (*models.UserRole, error) {
	return nil, models.ErrRoleNotFound
}
func (r *fakeUserRoleRepo) GetByUserAndRole(ctx context.Context, tenantID, userID, roleID uuid.UUID) (*models.UserRole, error) {
	return nil, models.ErrRoleNotFound
}
func (r *fakeUserRoleRepo) Delete(ctx context.Context, tenantID, userID, roleID uuid.UUID) error {
	return nil
}
func (r *fakeUserRoleRepo) GetUserRoles(ctx context.Context, tenantID, userID uuid.UUID) ([]*models.UserRole, error) {
	var out []*models.UserRole
	for _, ur := range r.userRoles {
		if ur.TenantID == tenantID && ur.UserID == userID {
			out = append(out, ur)
		}
	}
	return out, nil
}
func (r *fakeUserRoleRepo) GetRoleUsers(ctx context.Context, tenantID, roleID uuid.UUID) ([]*models.UserRole, error) {
	return nil, nil
}
func (r *fakeUserRoleRepo) DeleteExpired(ctx context.Context) error { return nil }

type fakeRolePermissionRepo struct{ grants []*models.RolePermission }

func (r *fakeRolePermissionRepo) Create(ctx context.Context, rp *models.RolePermission) error {
	r.grants = append(r.grants, rp)
	return nil
}
func (r *fakeRolePermissionRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.RolePermission, error) {
	return nil, models.ErrPermissionNotFound
}
func (r *fakeRolePermissionRepo) GetByRoleAndPermission(ctx context.Context, roleID, permissionID uuid.UUID) (*models.RolePermission, error) {
	return nil, models.ErrPermissionNotFound
}
func (r *fakeRolePermissionRepo) Delete(ctx context.Context, roleID, permissionID uuid.UUID) error {
	kept := r.grants[:0]
	for _, rp := range r.grants {
		if rp.RoleID != roleID || rp.PermissionID != permissionID {
			kept = append(kept, rp)
		}
	}
	r.grants = kept
	return nil
}
func (r *fakeRolePermissionRepo) GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]*models.RolePermission, error) {
	var out []*models.RolePermission
	for _, rp := range r.grants {
		if rp.RoleID == roleID {
			out = append(out, rp)
		}
	}
	return out, nil
}
func (r *fakeRolePermissionRepo) GetPermissionRoles(ctx context.Context, permissionID uuid.UUID) ([]*models.RolePermission, error) {
	var out []*models.RolePermission
	for _, rp := range r.grants {
		if rp.PermissionID == permissionID {
			out = append(out, rp)
		}
	}
	return out, nil
}

// --- fixture ---

type rbacFixture struct {
	tenantID        uuid.UUID
	userID          uuid.UUID
	roles           *fakeRoleRepo
	permissions     *fakePermissionRepo
	userRoles       *fakeUserRoleRepo
	rolePermissions *fakeRolePermissionRepo
	svc             services.PermissionService
}

func newRBACFixture() *rbacFixture {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	f := &rbacFixture{
		tenantID:        uuid.New(),
		userID:          uuid.New(),
		roles:           &fakeRoleRepo{roles: map[uuid.UUID]*models.Role{}},
		permissions:     &fakePermissionRepo{permissions: map[uuid.UUID]*models.Permission{}},
		userRoles:       &fakeUserRoleRepo{},
		rolePermissions: &fakeRolePermissionRepo{},
	}
	f.svc = services.NewPermissionService(f.permissions, f.roles, f.userRoles, f.rolePermissions, logger)
	return f
}

func (f *rbacFixture) addPermission(name, resource, action string) *models.Permission {
	p := &models.Permission{ID: uuid.New(), Name: name, Resource: resource, Action: action}
	f.permissions.permissions[p.ID] = p
	return p
}

func (f *rbacFixture) addRole(active bool, perms ...*models.Permission) *models.Role {
	role := &models.Role{ID: uuid.New(), TenantID: f.tenantID, IsActive: active}
	f.roles.roles[role.ID] = role
	for _, p := range perms {
		f.rolePermissions.grants = append(f.rolePermissions.grants, &models.RolePermission{ID: uuid.New(), RoleID: role.ID, PermissionID: p.ID})
	}
	return role
}

func (f *rbacFixture) assign(role *models.Role, expiresAt *time.Time) {
	f.userRoles.userRoles = append(f.userRoles.userRoles, &models.UserRole{
		ID: uuid.New(), TenantID: f.tenantID, UserID: f.userID, RoleID: role.ID, ExpiresAt: expiresAt,
	})
}

// --- tests ---

func TestGetUserPermissions_OverlappingRoles_ReturnsDeduplicatedSet(t *testing.T) {
	// Arrange
	f := newRBACFixture()
	read := f.addPermission("users:read", "users", "read")
	write := f.addPermission("users:write", "users", "write")
	f.assign(f.addRole(true, read), nil)
	f.assign(f.addRole(true, read, write), nil)

	// Act
	perms, err := f.svc.GetUserPermissions(context.Background(), f.tenantID, f.userID)

	// Assert
	require.NoError(t, err)
	assert.ElementsMatch(t, []*models.Permission{read, write}, perms)
}

func TestGetUserPermissions_ExpiredOrInactiveRole_IsIgnored(t *testing.T) {
	// Arrange
	f := newRBACFixture()
	expired := f.addPermission("clients:delete", "clients", "delete")
	inactive := f.addPermission("tenants:write", "tenants", "write")
	past := time.Now().Add(-time.Hour)
	f.assign(f.addRole(true, expired), &past)
	f.assign(f.addRole(false, inactive), nil)

	// Act
	perms, err := f.svc.GetUserPermissions(context.Background(), f.tenantID, f.userID)

	// Assert
	require.NoError(t, err)
	assert.Empty(t, perms)
}

func TestGetUserPermissions_OtherTenant_ReturnsNothing(t *testing.T) {
	// Arrange
	f := newRBACFixture()
	f.assign(f.addRole(true, f.addPermission("users:read", "users", "read")), nil)

	// Act
	perms, err := f.svc.GetUserPermissions(context.Background(), uuid.New(), f.userID)

	// Assert
	require.NoError(t, err)
	assert.Empty(t, perms)
}

func TestHasPermission_MatchingResourceAndAction_ReturnsTrue(t *testing.T) {
	// Arrange
	f := newRBACFixture()
	f.assign(f.addRole(true, f.addPermission("users:read", "users", "read")), nil)
	ctx := context.Background()

	// Act
	allowed, err := f.svc.HasPermission(ctx, f.tenantID, f.userID, "users", "read")
	denied, err2 := f.svc.HasPermission(ctx, f.tenantID, f.userID, "users", "write")

	// Assert
	require.NoError(t, err)
	require.NoError(t, err2)
	assert.True(t, allowed)
	assert.False(t, denied)
}

func TestCreatePermission_DuplicateName_ReturnsDuplicateResource(t *testing.T) {
	// Arrange
	f := newRBACFixture()
	f.addPermission("users:read", "users", "read")

	// Act
	_, err := f.svc.Create(context.Background(), &models.CreatePermissionRequest{
		Name: "users:read", DisplayName: "Read users", Resource: "users", Action: "read",
	})

	// Assert
	assert.Equal(t, models.ErrDuplicateResource, err)
}

func TestDeletePermission_GrantedToRoles_DetachesFromEveryRole(t *testing.T) {
	// Arrange
	f := newRBACFixture()
	p := f.addPermission("users:read", "users", "read")
	f.addRole(true, p)
	f.addRole(true, p)

	// Act
	err := f.svc.Delete(context.Background(), p.ID)

	// Assert
	require.NoError(t, err)
	assert.Empty(t, f.rolePermissions.grants)
	_, getErr := f.svc.GetByID(context.Background(), p.ID)
	assert.Equal(t, models.ErrPermissionNotFound, getErr)
}

func TestDeletePermission_SystemPermission_ReturnsBusinessRuleViolation(t *testing.T) {
	// Arrange
	f := newRBACFixture()
	p := f.addPermission("system:admin", "system", "admin")
	p.IsSystem = true

	// Act
	err := f.svc.Delete(context.Background(), p.ID)

	// Assert
	assert.Equal(t, models.ErrBusinessRuleViolation, err)
}

func TestHasPermission_ManagePermission_CoversEveryAction(t *testing.T) {
	// Arrange
	f := newRBACFixture()
	f.assign(f.addRole(true, f.addPermission("users.manage", "user", "manage")), nil)
	ctx := context.Background()

	// Act
	canDelete, err := f.svc.HasPermission(ctx, f.tenantID, f.userID, "user", "delete")
	canReadClients, err2 := f.svc.HasPermission(ctx, f.tenantID, f.userID, "client", "read")

	// Assert
	require.NoError(t, err)
	require.NoError(t, err2)
	assert.True(t, canDelete)
	assert.False(t, canReadClients)
}
