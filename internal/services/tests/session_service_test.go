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

// --- in-memory Session repo ---

type memSessionRepo struct {
	records map[uuid.UUID]*models.Session
}

func newMemSessionRepo() *memSessionRepo {
	return &memSessionRepo{records: make(map[uuid.UUID]*models.Session)}
}

func (r *memSessionRepo) Create(_ context.Context, s *models.Session) error {
	r.records[s.ID] = s
	return nil
}
func (r *memSessionRepo) GetByID(_ context.Context, _, id uuid.UUID) (*models.Session, error) {
	s, ok := r.records[id]
	if !ok {
		return nil, models.ErrSessionNotFound
	}
	return s, nil
}
func (r *memSessionRepo) GetByTokenID(_ context.Context, tokenID string) (*models.Session, error) {
	for _, s := range r.records {
		if s.TokenID == tokenID {
			return s, nil
		}
	}
	return nil, models.ErrSessionNotFound
}
func (r *memSessionRepo) ListByUser(_ context.Context, tenantID, userID uuid.UUID, limit, offset int) ([]*models.Session, int64, error) {
	var out []*models.Session
	for _, s := range r.records {
		if s.TenantID == tenantID && s.UserID == userID {
			out = append(out, s)
		}
	}
	return out, int64(len(out)), nil
}
func (r *memSessionRepo) Update(_ context.Context, s *models.Session) error {
	r.records[s.ID] = s
	return nil
}
func (r *memSessionRepo) Revoke(_ context.Context, _, id uuid.UUID) error {
	if s, ok := r.records[id]; ok {
		now := time.Now()
		s.RevokedAt = &now
	}
	return nil
}
func (r *memSessionRepo) RevokeAll(_ context.Context, tenantID, userID uuid.UUID) error {
	for _, s := range r.records {
		if s.TenantID == tenantID && s.UserID == userID {
			now := time.Now()
			s.RevokedAt = &now
		}
	}
	return nil
}
func (r *memSessionRepo) DeleteExpired(_ context.Context) error { return nil }

// --- tests ---

func TestSession_IsActive(t *testing.T) {
	s := &models.Session{
		ExpiresAt: time.Now().Add(time.Hour),
		RevokedAt: nil,
	}
	assert.True(t, s.IsActive())
}

func TestSession_IsExpired(t *testing.T) {
	s := &models.Session{ExpiresAt: time.Now().Add(-time.Hour)}
	assert.True(t, s.IsExpired())
	assert.False(t, s.IsActive())
}

func TestSession_IsRevoked(t *testing.T) {
	now := time.Now()
	s := &models.Session{ExpiresAt: time.Now().Add(time.Hour), RevokedAt: &now}
	assert.True(t, s.IsRevoked())
	assert.False(t, s.IsActive())
}

func TestSessionRepo_CreateAndGet(t *testing.T) {
	repo := newMemSessionRepo()
	tenantID, userID := uuid.New(), uuid.New()
	session := &models.Session{
		ID:        uuid.New(),
		TenantID:  tenantID,
		UserID:    userID,
		TokenID:   "tok-abc",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	require.NoError(t, repo.Create(context.Background(), session))

	got, err := repo.GetByID(context.Background(), tenantID, session.ID)
	require.NoError(t, err)
	assert.Equal(t, "tok-abc", got.TokenID)
}

func TestSessionRepo_GetByTokenID(t *testing.T) {
	repo := newMemSessionRepo()
	session := &models.Session{
		ID:        uuid.New(),
		TenantID:  uuid.New(),
		UserID:    uuid.New(),
		TokenID:   "unique-token-id",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	_ = repo.Create(context.Background(), session)
	got, err := repo.GetByTokenID(context.Background(), "unique-token-id")
	require.NoError(t, err)
	assert.Equal(t, session.ID, got.ID)
}

func TestSessionRepo_Revoke(t *testing.T) {
	repo := newMemSessionRepo()
	tenantID, sessionID := uuid.New(), uuid.New()
	_ = repo.Create(context.Background(), &models.Session{
		ID: sessionID, TenantID: tenantID, UserID: uuid.New(),
		TokenID: "t1", ExpiresAt: time.Now().Add(time.Hour),
	})
	require.NoError(t, repo.Revoke(context.Background(), tenantID, sessionID))
	got, _ := repo.GetByID(context.Background(), tenantID, sessionID)
	assert.NotNil(t, got.RevokedAt)
}

func TestSessionRepo_RevokeAll(t *testing.T) {
	repo := newMemSessionRepo()
	tenantID, userID := uuid.New(), uuid.New()
	for i := 0; i < 3; i++ {
		_ = repo.Create(context.Background(), &models.Session{
			ID: uuid.New(), TenantID: tenantID, UserID: userID,
			TokenID: uuid.New().String(), ExpiresAt: time.Now().Add(time.Hour),
		})
	}
	require.NoError(t, repo.RevokeAll(context.Background(), tenantID, userID))
	sessions, _, _ := repo.ListByUser(context.Background(), tenantID, userID, 10, 0)
	for _, s := range sessions {
		assert.NotNil(t, s.RevokedAt, "session %s should be revoked", s.ID)
	}
}
