package tests

import (
	"context"
	"testing"
	"time"

	"shieldgate/internal/models"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- in-memory SocialProvider repo ---

type memSocialProviderRepo struct {
	records map[string]*models.SocialProvider // key: tenantID+":"+provider
}

func newMemSocialProviderRepo() *memSocialProviderRepo {
	return &memSocialProviderRepo{records: make(map[string]*models.SocialProvider)}
}

func (r *memSocialProviderRepo) key(tenantID uuid.UUID, provider string) string {
	return tenantID.String() + ":" + provider
}

func (r *memSocialProviderRepo) Create(_ context.Context, p *models.SocialProvider) error {
	k := r.key(p.TenantID, p.Provider)
	if _, exists := r.records[k]; exists {
		return models.ErrDuplicateResource
	}
	r.records[k] = p
	return nil
}

func (r *memSocialProviderRepo) GetByTenantAndProvider(_ context.Context, tenantID uuid.UUID, provider string) (*models.SocialProvider, error) {
	p, ok := r.records[r.key(tenantID, provider)]
	if !ok {
		return nil, models.ErrSocialProviderNotConfigured
	}
	return p, nil
}

func (r *memSocialProviderRepo) List(_ context.Context, tenantID uuid.UUID) ([]*models.SocialProvider, error) {
	var out []*models.SocialProvider
	for _, p := range r.records {
		if p.TenantID == tenantID {
			out = append(out, p)
		}
	}
	return out, nil
}

func (r *memSocialProviderRepo) Update(_ context.Context, p *models.SocialProvider) error {
	r.records[r.key(p.TenantID, p.Provider)] = p
	return nil
}

func (r *memSocialProviderRepo) Delete(_ context.Context, tenantID uuid.UUID, provider string) error {
	delete(r.records, r.key(tenantID, provider))
	return nil
}

// --- in-memory SocialAccount repo ---

type memSocialAccountRepo struct {
	records map[uuid.UUID]*models.SocialAccount
}

func newMemSocialAccountRepo() *memSocialAccountRepo {
	return &memSocialAccountRepo{records: make(map[uuid.UUID]*models.SocialAccount)}
}

func (r *memSocialAccountRepo) Create(_ context.Context, a *models.SocialAccount) error {
	for _, existing := range r.records {
		if existing.Provider == a.Provider && existing.ExternalID == a.ExternalID {
			return models.ErrSocialAccountExists
		}
	}
	r.records[a.ID] = a
	return nil
}

func (r *memSocialAccountRepo) GetByProviderAndExternalID(_ context.Context, provider, externalID string) (*models.SocialAccount, error) {
	for _, a := range r.records {
		if a.Provider == provider && a.ExternalID == externalID {
			return a, nil
		}
	}
	return nil, models.ErrSocialAccountNotFound
}

func (r *memSocialAccountRepo) GetByUserAndProvider(_ context.Context, _, userID uuid.UUID, provider string) (*models.SocialAccount, error) {
	for _, a := range r.records {
		if a.UserID == userID && a.Provider == provider {
			return a, nil
		}
	}
	return nil, models.ErrSocialAccountNotFound
}

func (r *memSocialAccountRepo) ListByUser(_ context.Context, _, userID uuid.UUID) ([]*models.SocialAccount, error) {
	var out []*models.SocialAccount
	for _, a := range r.records {
		if a.UserID == userID {
			out = append(out, a)
		}
	}
	return out, nil
}

func (r *memSocialAccountRepo) Update(_ context.Context, a *models.SocialAccount) error {
	r.records[a.ID] = a
	return nil
}

func (r *memSocialAccountRepo) Delete(_ context.Context, _, userID uuid.UUID, provider string) error {
	for id, a := range r.records {
		if a.UserID == userID && a.Provider == provider {
			delete(r.records, id)
			return nil
		}
	}
	return models.ErrSocialAccountNotFound
}

// --- tests ---

func TestSocialProvider_CreateAndGet(t *testing.T) {
	repo := newMemSocialProviderRepo()
	tenantID := uuid.New()
	p := &models.SocialProvider{
		ID:       uuid.New(),
		TenantID: tenantID,
		Provider: "google",
		ClientID: "cid-123",
		IsActive: true,
	}
	require.NoError(t, repo.Create(context.Background(), p))

	got, err := repo.GetByTenantAndProvider(context.Background(), tenantID, "google")
	require.NoError(t, err)
	assert.Equal(t, "cid-123", got.ClientID)
}

func TestSocialProvider_DuplicateReturnsError(t *testing.T) {
	repo := newMemSocialProviderRepo()
	tenantID := uuid.New()
	p := &models.SocialProvider{ID: uuid.New(), TenantID: tenantID, Provider: "github"}
	require.NoError(t, repo.Create(context.Background(), p))
	err := repo.Create(context.Background(), &models.SocialProvider{ID: uuid.New(), TenantID: tenantID, Provider: "github"})
	assert.ErrorIs(t, err, models.ErrDuplicateResource)
}

func TestSocialProvider_List(t *testing.T) {
	repo := newMemSocialProviderRepo()
	tenantID := uuid.New()
	for _, name := range []string{"google", "github", "facebook"} {
		_ = repo.Create(context.Background(), &models.SocialProvider{ID: uuid.New(), TenantID: tenantID, Provider: name})
	}
	list, err := repo.List(context.Background(), tenantID)
	require.NoError(t, err)
	assert.Len(t, list, 3)
}

func TestSocialProvider_Delete(t *testing.T) {
	repo := newMemSocialProviderRepo()
	tenantID := uuid.New()
	_ = repo.Create(context.Background(), &models.SocialProvider{ID: uuid.New(), TenantID: tenantID, Provider: "google"})
	require.NoError(t, repo.Delete(context.Background(), tenantID, "google"))
	_, err := repo.GetByTenantAndProvider(context.Background(), tenantID, "google")
	assert.Error(t, err)
}

func TestSocialAccount_LinkAndList(t *testing.T) {
	repo := newMemSocialAccountRepo()
	userID, tenantID := uuid.New(), uuid.New()
	account := &models.SocialAccount{
		ID:         uuid.New(),
		TenantID:   tenantID,
		UserID:     userID,
		Provider:   "google",
		ExternalID: "google-uid-42",
		Email:      "user@example.com",
	}
	require.NoError(t, repo.Create(context.Background(), account))

	list, err := repo.ListByUser(context.Background(), tenantID, userID)
	require.NoError(t, err)
	assert.Len(t, list, 1)
	assert.Equal(t, "google-uid-42", list[0].ExternalID)
}

func TestSocialAccount_UnlinkAccount(t *testing.T) {
	repo := newMemSocialAccountRepo()
	userID, tenantID := uuid.New(), uuid.New()
	_ = repo.Create(context.Background(), &models.SocialAccount{
		ID: uuid.New(), TenantID: tenantID, UserID: userID,
		Provider: "github", ExternalID: "gh-99",
	})
	require.NoError(t, repo.Delete(context.Background(), tenantID, userID, "github"))
	list, _ := repo.ListByUser(context.Background(), tenantID, userID)
	assert.Empty(t, list)
}

func TestSocialAccount_GetByProviderAndExternalID(t *testing.T) {
	repo := newMemSocialAccountRepo()
	_ = repo.Create(context.Background(), &models.SocialAccount{
		ID: uuid.New(), TenantID: uuid.New(), UserID: uuid.New(),
		Provider: "google", ExternalID: "uid-xyz",
	})
	got, err := repo.GetByProviderAndExternalID(context.Background(), "google", "uid-xyz")
	require.NoError(t, err)
	assert.Equal(t, "uid-xyz", got.ExternalID)
}

func TestSocialAccount_DuplicateLinkReturnsError(t *testing.T) {
	repo := newMemSocialAccountRepo()
	a := &models.SocialAccount{
		ID: uuid.New(), TenantID: uuid.New(), UserID: uuid.New(),
		Provider: "twitter", ExternalID: "tw-1",
	}
	require.NoError(t, repo.Create(context.Background(), a))
	err := repo.Create(context.Background(), &models.SocialAccount{
		ID: uuid.New(), TenantID: uuid.New(), UserID: uuid.New(),
		Provider: "twitter", ExternalID: "tw-1",
	})
	assert.ErrorIs(t, err, models.ErrSocialAccountExists)
}

func TestSocialProvider_GetNotFound(t *testing.T) {
	repo := newMemSocialProviderRepo()
	_, err := repo.GetByTenantAndProvider(context.Background(), uuid.New(), "nonexistent")
	assert.Error(t, err)
}

func TestSocialAccount_Update(t *testing.T) {
	repo := newMemSocialAccountRepo()
	userID := uuid.New()
	a := &models.SocialAccount{
		ID:         uuid.New(),
		TenantID:   uuid.New(),
		UserID:     userID,
		Provider:   "google",
		ExternalID: "g-1",
		Email:      "old@example.com",
	}
	_ = repo.Create(context.Background(), a)
	a.Email = "new@example.com"
	require.NoError(t, repo.Update(context.Background(), a))
	got, _ := repo.GetByProviderAndExternalID(context.Background(), "google", "g-1")
	assert.Equal(t, "new@example.com", got.Email)
}

func TestSocialProvider_Update(t *testing.T) {
	repo := newMemSocialProviderRepo()
	tenantID := uuid.New()
	p := &models.SocialProvider{
		ID: uuid.New(), TenantID: tenantID, Provider: "google",
		ClientID: "old-id", IsActive: true,
	}
	_ = repo.Create(context.Background(), p)
	p.ClientID = "new-id"
	require.NoError(t, repo.Update(context.Background(), p))
	got, _ := repo.GetByTenantAndProvider(context.Background(), tenantID, "google")
	assert.Equal(t, "new-id", got.ClientID)
}

func TestSocialProvider_IsolatedByTenant(t *testing.T) {
	repo := newMemSocialProviderRepo()
	tenant1, tenant2 := uuid.New(), uuid.New()
	_ = repo.Create(context.Background(), &models.SocialProvider{
		ID: uuid.New(), TenantID: tenant1, Provider: "google",
	})
	_ = repo.Create(context.Background(), &models.SocialProvider{
		ID: uuid.New(), TenantID: tenant2, Provider: "google",
	})
	list1, _ := repo.List(context.Background(), tenant1)
	list2, _ := repo.List(context.Background(), tenant2)
	assert.Len(t, list1, 1)
	assert.Len(t, list2, 1)
	// Should not share records
	assert.NotEqual(t, list1[0].ID, list2[0].ID)
}

// Verify models.SocialProvider zero-value used_at behavior (model sanity)
func TestSocialAccount_TokenExpiry(t *testing.T) {
	now := time.Now()
	a := &models.SocialAccount{TokenExpiresAt: &now}
	assert.NotNil(t, a.TokenExpiresAt)
}
