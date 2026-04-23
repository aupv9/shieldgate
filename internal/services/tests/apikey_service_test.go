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

// --- in-memory APIKey repo ---

type memAPIKeyRepo struct {
	records map[uuid.UUID]*models.APIKey
}

func newMemAPIKeyRepo() *memAPIKeyRepo {
	return &memAPIKeyRepo{records: make(map[uuid.UUID]*models.APIKey)}
}

func (r *memAPIKeyRepo) Create(_ context.Context, k *models.APIKey) error {
	for _, existing := range r.records {
		if existing.KeyHash == k.KeyHash {
			return models.ErrDuplicateResource
		}
	}
	r.records[k.ID] = k
	return nil
}

func (r *memAPIKeyRepo) GetByID(_ context.Context, tenantID, id uuid.UUID) (*models.APIKey, error) {
	k, ok := r.records[id]
	if !ok || k.TenantID != tenantID {
		return nil, models.ErrAPIKeyNotFound
	}
	return k, nil
}

func (r *memAPIKeyRepo) GetByHash(_ context.Context, hash string) (*models.APIKey, error) {
	for _, k := range r.records {
		if k.KeyHash == hash {
			return k, nil
		}
	}
	return nil, models.ErrAPIKeyNotFound
}

func (r *memAPIKeyRepo) List(_ context.Context, tenantID uuid.UUID, userID *uuid.UUID, limit, offset int) ([]*models.APIKey, int64, error) {
	var out []*models.APIKey
	for _, k := range r.records {
		if k.TenantID != tenantID {
			continue
		}
		if userID != nil && (k.UserID == nil || *k.UserID != *userID) {
			continue
		}
		out = append(out, k)
	}
	total := int64(len(out))
	if offset >= len(out) {
		return []*models.APIKey{}, total, nil
	}
	end := offset + limit
	if end > len(out) {
		end = len(out)
	}
	return out[offset:end], total, nil
}

func (r *memAPIKeyRepo) Revoke(_ context.Context, tenantID, id uuid.UUID) error {
	if k, ok := r.records[id]; ok && k.TenantID == tenantID {
		now := time.Now()
		k.RevokedAt = &now
		return nil
	}
	return models.ErrAPIKeyNotFound
}

func (r *memAPIKeyRepo) UpdateLastUsed(_ context.Context, id uuid.UUID) error {
	if k, ok := r.records[id]; ok {
		now := time.Now()
		k.LastUsedAt = &now
	}
	return nil
}

func (r *memAPIKeyRepo) Delete(_ context.Context, tenantID, id uuid.UUID) error {
	if k, ok := r.records[id]; ok && k.TenantID == tenantID {
		delete(r.records, id)
		return nil
	}
	return models.ErrAPIKeyNotFound
}

// --- model method tests ---

func TestAPIKey_IsActive_ActiveKey(t *testing.T) {
	k := &models.APIKey{
		RevokedAt: nil,
		ExpiresAt: nil,
	}
	assert.True(t, k.IsActive())
	assert.False(t, k.IsRevoked())
	assert.False(t, k.IsExpired())
}

func TestAPIKey_IsRevoked(t *testing.T) {
	now := time.Now()
	k := &models.APIKey{RevokedAt: &now}
	assert.True(t, k.IsRevoked())
	assert.False(t, k.IsActive())
}

func TestAPIKey_IsExpired(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	k := &models.APIKey{ExpiresAt: &past}
	assert.True(t, k.IsExpired())
	assert.False(t, k.IsActive())
}

func TestAPIKey_NotExpiredWithFutureExpiry(t *testing.T) {
	future := time.Now().Add(time.Hour)
	k := &models.APIKey{ExpiresAt: &future}
	assert.False(t, k.IsExpired())
	assert.True(t, k.IsActive())
}

// --- repo tests ---

func TestAPIKeyRepo_CreateAndGetByID(t *testing.T) {
	repo := newMemAPIKeyRepo()
	tenantID := uuid.New()
	key := &models.APIKey{
		ID:       uuid.New(),
		TenantID: tenantID,
		Name:     "test-key",
		KeyHash:  "hash-abc",
		LastFour: "xabc",
		Prefix:   "sg",
		Scopes:   models.StringArray{"read"},
	}
	require.NoError(t, repo.Create(context.Background(), key))

	got, err := repo.GetByID(context.Background(), tenantID, key.ID)
	require.NoError(t, err)
	assert.Equal(t, "test-key", got.Name)
}

func TestAPIKeyRepo_GetByHash(t *testing.T) {
	repo := newMemAPIKeyRepo()
	key := &models.APIKey{
		ID: uuid.New(), TenantID: uuid.New(),
		Name: "ci-key", KeyHash: "sha256-hash-xyz", LastFour: "wxyz", Prefix: "aa",
	}
	_ = repo.Create(context.Background(), key)
	got, err := repo.GetByHash(context.Background(), "sha256-hash-xyz")
	require.NoError(t, err)
	assert.Equal(t, "ci-key", got.Name)
}

func TestAPIKeyRepo_Revoke(t *testing.T) {
	repo := newMemAPIKeyRepo()
	tenantID := uuid.New()
	key := &models.APIKey{ID: uuid.New(), TenantID: tenantID, KeyHash: "h1", LastFour: "0000", Prefix: "aa"}
	_ = repo.Create(context.Background(), key)
	require.NoError(t, repo.Revoke(context.Background(), tenantID, key.ID))
	got, _ := repo.GetByID(context.Background(), tenantID, key.ID)
	assert.NotNil(t, got.RevokedAt)
	assert.True(t, got.IsRevoked())
}

func TestAPIKeyRepo_Delete(t *testing.T) {
	repo := newMemAPIKeyRepo()
	tenantID := uuid.New()
	key := &models.APIKey{ID: uuid.New(), TenantID: tenantID, KeyHash: "h2", LastFour: "0000", Prefix: "aa"}
	_ = repo.Create(context.Background(), key)
	require.NoError(t, repo.Delete(context.Background(), tenantID, key.ID))
	_, err := repo.GetByID(context.Background(), tenantID, key.ID)
	assert.ErrorIs(t, err, models.ErrAPIKeyNotFound)
}

func TestAPIKeyRepo_List_FilterByUser(t *testing.T) {
	repo := newMemAPIKeyRepo()
	tenantID := uuid.New()
	userA := uuid.New()
	userB := uuid.New()
	_ = repo.Create(context.Background(), &models.APIKey{
		ID: uuid.New(), TenantID: tenantID, UserID: &userA,
		KeyHash: "h3", LastFour: "aaaa", Prefix: "bb",
	})
	_ = repo.Create(context.Background(), &models.APIKey{
		ID: uuid.New(), TenantID: tenantID, UserID: &userB,
		KeyHash: "h4", LastFour: "bbbb", Prefix: "cc",
	})
	listA, total, _ := repo.List(context.Background(), tenantID, &userA, 10, 0)
	assert.Equal(t, int64(1), total)
	assert.Len(t, listA, 1)
}

func TestAPIKeyRepo_DuplicateHash(t *testing.T) {
	repo := newMemAPIKeyRepo()
	tenantID := uuid.New()
	_ = repo.Create(context.Background(), &models.APIKey{
		ID: uuid.New(), TenantID: tenantID, KeyHash: "same-hash", LastFour: "zzzz", Prefix: "dd",
	})
	err := repo.Create(context.Background(), &models.APIKey{
		ID: uuid.New(), TenantID: tenantID, KeyHash: "same-hash", LastFour: "zzzz", Prefix: "dd",
	})
	assert.ErrorIs(t, err, models.ErrDuplicateResource)
}

func TestAPIKeyRepo_UpdateLastUsed(t *testing.T) {
	repo := newMemAPIKeyRepo()
	tenantID := uuid.New()
	key := &models.APIKey{
		ID: uuid.New(), TenantID: tenantID,
		KeyHash: "h5", LastFour: "cccc", Prefix: "ee",
	}
	_ = repo.Create(context.Background(), key)
	require.NoError(t, repo.UpdateLastUsed(context.Background(), key.ID))
	got, _ := repo.GetByID(context.Background(), tenantID, key.ID)
	assert.NotNil(t, got.LastUsedAt)
}

func TestAPIKeyRepo_TenantIsolation(t *testing.T) {
	repo := newMemAPIKeyRepo()
	t1, t2 := uuid.New(), uuid.New()
	_ = repo.Create(context.Background(), &models.APIKey{
		ID: uuid.New(), TenantID: t1, KeyHash: "h6", LastFour: "1111", Prefix: "ff",
	})
	_ = repo.Create(context.Background(), &models.APIKey{
		ID: uuid.New(), TenantID: t2, KeyHash: "h7", LastFour: "2222", Prefix: "gg",
	})
	list, total, _ := repo.List(context.Background(), t1, nil, 10, 0)
	assert.Equal(t, int64(1), total)
	assert.Len(t, list, 1)
}
