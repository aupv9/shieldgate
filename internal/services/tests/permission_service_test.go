package tests

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"shieldgate/internal/models"
	"shieldgate/internal/services"
)

// ─── Mock Repositories ───────────────────────────────────────────────────────

type mockPermissionRepo struct {
	permissions map[uuid.UUID]*models.Permission
	byName      map[string]*models.Permission
}

func newMockPermissionRepo() *mockPermissionRepo {
	return &mockPermissionRepo{
		permissions: make(map[uuid.UUID]*models.Permission),
		byName:      make(map[string]*models.Permission),
	}
}

func (m *mockPermissionRepo) Create(_ context.Context, p *models.Permission) error {
	m.permissions[p.ID] = p
	m.byName[p.Name] = p
	return nil
}

func (m *mockPermissionRepo) GetByID(_ context.Context, id uuid.UUID) (*models.Permission, error) {
	p, ok := m.permissions[id]
	if !ok {
		return nil, models.ErrPermissionNotFound
	}
	return p, nil
}

func (m *mockPermissionRepo) GetByName(_ context.Context, name string) (*models.Permission, error) {
	p, ok := m.byName[name]
	if !ok {
		return nil, models.ErrPermissionNotFound
	}
	return p, nil
}

func (m *mockPermissionRepo) Update(_ context.Context, p *models.Permission) error {
	m.permissions[p.ID] = p
	m.byName[p.Name] = p
	return nil
}

func (m *mockPermissionRepo) Delete(_ context.Context, id uuid.UUID) error {
	if p, ok := m.permissions[id]; ok {
		delete(m.byName, p.Name)
		delete(m.permissions, id)
	}
	return nil
}

func (m *mockPermissionRepo) List(_ context.Context, limit, offset int) ([]*models.Permission, int64, error) {
	var all []*models.Permission
	for _, p := range m.permissions {
		all = append(all, p)
	}
	total := int64(len(all))
	end := offset + limit
	if end > len(all) {
		end = len(all)
	}
	if offset >= len(all) {
		return nil, total, nil
	}
	return all[offset:end], total, nil
}

func (m *mockPermissionRepo) GetByResource(_ context.Context, resource string) ([]*models.Permission, error) {
	var result []*models.Permission
	for _, p := range m.permissions {
		if p.Resource == resource {
			result = append(result, p)
		}
	}
	return result, nil
}

type mockUserRoleRepo struct {
	userRoles []*models.UserRole
}

func (m *mockUserRoleRepo) Create(_ context.Context, ur *models.UserRole) error {
	m.userRoles = append(m.userRoles, ur)
	return nil
}

func (m *mockUserRoleRepo) GetByID(_ context.Context, _, id uuid.UUID) (*models.UserRole, error) {
	for _, ur := range m.userRoles {
		if ur.ID == id {
			return ur, nil
		}
	}
	return nil, models.ErrResourceNotFound
}

func (m *mockUserRoleRepo) GetByUserAndRole(_ context.Context, tenantID, userID, roleID uuid.UUID) (*models.UserRole, error) {
	for _, ur := range m.userRoles {
		if ur.TenantID == tenantID && ur.UserID == userID && ur.RoleID == roleID {
			return ur, nil
		}
	}
	return nil, models.ErrResourceNotFound
}

func (m *mockUserRoleRepo) Delete(_ context.Context, tenantID, userID, roleID uuid.UUID) error {
	for i, ur := range m.userRoles {
		if ur.TenantID == tenantID && ur.UserID == userID && ur.RoleID == roleID {
			m.userRoles = append(m.userRoles[:i], m.userRoles[i+1:]...)
			return nil
		}
	}
	return nil
}

func (m *mockUserRoleRepo) GetUserRoles(_ context.Context, tenantID, userID uuid.UUID) ([]*models.UserRole, error) {
	var result []*models.UserRole
	for _, ur := range m.userRoles {
		if ur.TenantID == tenantID && ur.UserID == userID {
			result = append(result, ur)
		}
	}
	return result, nil
}

func (m *mockUserRoleRepo) GetRoleUsers(_ context.Context, tenantID, roleID uuid.UUID) ([]*models.UserRole, error) {
	var result []*models.UserRole
	for _, ur := range m.userRoles {
		if ur.TenantID == tenantID && ur.RoleID == roleID {
			result = append(result, ur)
		}
	}
	return result, nil
}

func (m *mockUserRoleRepo) DeleteExpired(_ context.Context) error { return nil }

type mockRolePermRepo struct {
	rolePerms []*models.RolePermission
}

func (m *mockRolePermRepo) Create(_ context.Context, rp *models.RolePermission) error {
	m.rolePerms = append(m.rolePerms, rp)
	return nil
}

func (m *mockRolePermRepo) GetByID(_ context.Context, id uuid.UUID) (*models.RolePermission, error) {
	for _, rp := range m.rolePerms {
		if rp.ID == id {
			return rp, nil
		}
	}
	return nil, models.ErrResourceNotFound
}

func (m *mockRolePermRepo) GetByRoleAndPermission(_ context.Context, roleID, permID uuid.UUID) (*models.RolePermission, error) {
	for _, rp := range m.rolePerms {
		if rp.RoleID == roleID && rp.PermissionID == permID {
			return rp, nil
		}
	}
	return nil, models.ErrResourceNotFound
}

func (m *mockRolePermRepo) Delete(_ context.Context, roleID, permID uuid.UUID) error {
	for i, rp := range m.rolePerms {
		if rp.RoleID == roleID && rp.PermissionID == permID {
			m.rolePerms = append(m.rolePerms[:i], m.rolePerms[i+1:]...)
			return nil
		}
	}
	return nil
}

func (m *mockRolePermRepo) GetRolePermissions(_ context.Context, roleID uuid.UUID) ([]*models.RolePermission, error) {
	var result []*models.RolePermission
	for _, rp := range m.rolePerms {
		if rp.RoleID == roleID {
			result = append(result, rp)
		}
	}
	return result, nil
}

func (m *mockRolePermRepo) GetPermissionRoles(_ context.Context, permID uuid.UUID) ([]*models.RolePermission, error) {
	var result []*models.RolePermission
	for _, rp := range m.rolePerms {
		if rp.PermissionID == permID {
			result = append(result, rp)
		}
	}
	return result, nil
}

// ─── Helper ──────────────────────────────────────────────────────────────────

func newTestPermissionService(permRepo *mockPermissionRepo, urRepo *mockUserRoleRepo, rpRepo *mockRolePermRepo) services.PermissionService {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)
	return services.NewPermissionService(permRepo, urRepo, rpRepo, logger)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

func TestPermissionService_Create_Success(t *testing.T) {
	svc := newTestPermissionService(newMockPermissionRepo(), &mockUserRoleRepo{}, &mockRolePermRepo{})

	req := &models.CreatePermissionRequest{
		Name:        "users.read",
		DisplayName: "Read Users",
		Resource:    "user",
		Action:      "read",
	}
	p, err := svc.Create(context.Background(), req)

	require.NoError(t, err)
	assert.Equal(t, "users.read", p.Name)
	assert.Equal(t, "user", p.Resource)
	assert.Equal(t, "read", p.Action)
}

func TestPermissionService_Create_Duplicate(t *testing.T) {
	permRepo := newMockPermissionRepo()
	svc := newTestPermissionService(permRepo, &mockUserRoleRepo{}, &mockRolePermRepo{})

	req := &models.CreatePermissionRequest{
		Name:        "users.read",
		DisplayName: "Read Users",
		Resource:    "user",
		Action:      "read",
	}
	_, err := svc.Create(context.Background(), req)
	require.NoError(t, err)

	_, err = svc.Create(context.Background(), req)
	assert.True(t, errors.Is(err, models.ErrDuplicateResource))
}

func TestPermissionService_Delete_SystemPermission_Rejected(t *testing.T) {
	permRepo := newMockPermissionRepo()
	id := uuid.New()
	systemPerm := &models.Permission{
		ID:       id,
		Name:     "system.perm",
		Resource: "system",
		Action:   "manage",
		IsSystem: true,
	}
	permRepo.permissions[id] = systemPerm
	permRepo.byName["system.perm"] = systemPerm

	svc := newTestPermissionService(permRepo, &mockUserRoleRepo{}, &mockRolePermRepo{})

	err := svc.Delete(context.Background(), id)
	assert.Error(t, err, "system permissions should not be deletable")
}

func TestPermissionService_HasPermission_ExactMatch(t *testing.T) {
	permRepo := newMockPermissionRepo()
	urRepo := &mockUserRoleRepo{}
	rpRepo := &mockRolePermRepo{}

	tenantID := uuid.New()
	userID := uuid.New()
	roleID := uuid.New()
	permID := uuid.New()

	perm := &models.Permission{ID: permID, Name: "users.read", Resource: "user", Action: "read"}
	permRepo.permissions[permID] = perm

	urRepo.userRoles = []*models.UserRole{
		{ID: uuid.New(), TenantID: tenantID, UserID: userID, RoleID: roleID, GrantedAt: time.Now()},
	}
	rpRepo.rolePerms = []*models.RolePermission{
		{ID: uuid.New(), RoleID: roleID, PermissionID: permID, Permission: *perm},
	}

	svc := newTestPermissionService(permRepo, urRepo, rpRepo)

	has, err := svc.HasPermission(context.Background(), tenantID, userID, "user", "read")
	require.NoError(t, err)
	assert.True(t, has)
}

func TestPermissionService_HasPermission_ManageGrantsAll(t *testing.T) {
	permRepo := newMockPermissionRepo()
	urRepo := &mockUserRoleRepo{}
	rpRepo := &mockRolePermRepo{}

	tenantID := uuid.New()
	userID := uuid.New()
	roleID := uuid.New()
	permID := uuid.New()

	managePerm := &models.Permission{ID: permID, Name: "users.manage", Resource: "user", Action: "manage"}
	permRepo.permissions[permID] = managePerm

	urRepo.userRoles = []*models.UserRole{
		{ID: uuid.New(), TenantID: tenantID, UserID: userID, RoleID: roleID, GrantedAt: time.Now()},
	}
	rpRepo.rolePerms = []*models.RolePermission{
		{ID: uuid.New(), RoleID: roleID, PermissionID: permID, Permission: *managePerm},
	}

	svc := newTestPermissionService(permRepo, urRepo, rpRepo)

	// "manage" should grant "delete"
	has, err := svc.HasPermission(context.Background(), tenantID, userID, "user", "delete")
	require.NoError(t, err)
	assert.True(t, has)
}

func TestPermissionService_HasPermission_ExpiredRole_Denied(t *testing.T) {
	permRepo := newMockPermissionRepo()
	urRepo := &mockUserRoleRepo{}
	rpRepo := &mockRolePermRepo{}

	tenantID := uuid.New()
	userID := uuid.New()
	roleID := uuid.New()
	permID := uuid.New()

	perm := &models.Permission{ID: permID, Name: "users.read", Resource: "user", Action: "read"}
	permRepo.permissions[permID] = perm

	past := time.Now().Add(-1 * time.Hour)
	urRepo.userRoles = []*models.UserRole{
		{ID: uuid.New(), TenantID: tenantID, UserID: userID, RoleID: roleID, ExpiresAt: &past},
	}
	rpRepo.rolePerms = []*models.RolePermission{
		{ID: uuid.New(), RoleID: roleID, PermissionID: permID, Permission: *perm},
	}

	svc := newTestPermissionService(permRepo, urRepo, rpRepo)

	has, err := svc.HasPermission(context.Background(), tenantID, userID, "user", "read")
	require.NoError(t, err)
	assert.False(t, has, "expired role should not grant permissions")
}

func TestPermissionService_HasPermission_NoRoles_Denied(t *testing.T) {
	svc := newTestPermissionService(newMockPermissionRepo(), &mockUserRoleRepo{}, &mockRolePermRepo{})

	has, err := svc.HasPermission(context.Background(), uuid.New(), uuid.New(), "user", "read")
	require.NoError(t, err)
	assert.False(t, has)
}

func TestPermissionService_GetUserPermissions_DeduplicatesAcrossRoles(t *testing.T) {
	permRepo := newMockPermissionRepo()
	urRepo := &mockUserRoleRepo{}
	rpRepo := &mockRolePermRepo{}

	tenantID := uuid.New()
	userID := uuid.New()
	roleID1 := uuid.New()
	roleID2 := uuid.New()
	permID := uuid.New()

	perm := &models.Permission{ID: permID, Name: "users.read", Resource: "user", Action: "read"}
	permRepo.permissions[permID] = perm

	urRepo.userRoles = []*models.UserRole{
		{ID: uuid.New(), TenantID: tenantID, UserID: userID, RoleID: roleID1},
		{ID: uuid.New(), TenantID: tenantID, UserID: userID, RoleID: roleID2},
	}
	// Both roles have the same permission — should appear once in result
	rpRepo.rolePerms = []*models.RolePermission{
		{ID: uuid.New(), RoleID: roleID1, PermissionID: permID, Permission: *perm},
		{ID: uuid.New(), RoleID: roleID2, PermissionID: permID, Permission: *perm},
	}

	svc := newTestPermissionService(permRepo, urRepo, rpRepo)

	perms, err := svc.GetUserPermissions(context.Background(), tenantID, userID)
	require.NoError(t, err)
	assert.Len(t, perms, 1, "duplicate permissions from multiple roles should be deduplicated")
}
