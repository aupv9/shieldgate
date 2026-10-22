package tests

// session_service_test.go covers SSO session lifecycle and remembered consent.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"shieldgate/internal/models"
	"shieldgate/internal/services"
)

type fakeSessionRepo struct {
	mu       sync.Mutex
	sessions map[string]*models.Session
}

func (r *fakeSessionRepo) Create(ctx context.Context, s *models.Session) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	stored := *s
	r.sessions[s.TokenHash] = &stored
	return nil
}

func (r *fakeSessionRepo) GetByTokenHash(ctx context.Context, tenantID uuid.UUID, hash string) (*models.Session, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.sessions[hash]; ok && s.TenantID == tenantID {
		copied := *s
		return &copied, nil
	}
	return nil, models.ErrSessionNotFound
}

func (r *fakeSessionRepo) DeleteByTokenHash(ctx context.Context, tenantID uuid.UUID, hash string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.sessions, hash)
	return nil
}

func (r *fakeSessionRepo) DeleteByUserID(ctx context.Context, tenantID, userID uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, s := range r.sessions {
		if s.TenantID == tenantID && s.UserID == userID {
			delete(r.sessions, k)
		}
	}
	return nil
}

func (r *fakeSessionRepo) DeleteExpired(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, s := range r.sessions {
		if s.IsExpired() {
			delete(r.sessions, k)
		}
	}
	return nil
}

// count returns the number of stored sessions
func (r *fakeSessionRepo) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sessions)
}

type fakeConsentRepo struct {
	consents map[[3]uuid.UUID]*models.Consent
}

func (r *fakeConsentRepo) Get(ctx context.Context, tenantID, userID, clientID uuid.UUID) (*models.Consent, error) {
	if c, ok := r.consents[[3]uuid.UUID{tenantID, userID, clientID}]; ok {
		copied := *c
		return &copied, nil
	}
	return nil, models.ErrResourceNotFound
}

func (r *fakeConsentRepo) Upsert(ctx context.Context, c *models.Consent) error {
	stored := *c
	r.consents[[3]uuid.UUID{c.TenantID, c.UserID, c.ClientID}] = &stored
	return nil
}

func (r *fakeConsentRepo) Delete(ctx context.Context, tenantID, userID, clientID uuid.UUID) error {
	delete(r.consents, [3]uuid.UUID{tenantID, userID, clientID})
	return nil
}

func newSessionService(duration time.Duration) (services.SessionService, *fakeSessionRepo) {
	sessions := &fakeSessionRepo{sessions: map[string]*models.Session{}}
	consents := &fakeConsentRepo{consents: map[[3]uuid.UUID]*models.Consent{}}
	return services.NewSessionService(sessions, consents, duration, quietLogger()), sessions
}

func TestSession_CreateThenGet_StoresOnlyTokenHash(t *testing.T) {
	// Arrange
	svc, repo := newSessionService(time.Hour)
	tenantID, userID := uuid.New(), uuid.New()

	// Act
	token, created, err := svc.CreateSession(context.Background(), tenantID, userID, "10.0.0.1", "ua")
	require.NoError(t, err)
	got, getErr := svc.GetSession(context.Background(), tenantID, token)

	// Assert
	require.NoError(t, getErr)
	assert.Equal(t, created.ID, got.ID)
	assert.Equal(t, userID, got.UserID)
	assert.WithinDuration(t, time.Now(), got.AuthTime, time.Second)
	assert.NotContains(t, repo.sessions, token, "raw token must not be the storage key")
	assert.GreaterOrEqual(t, len(token), 43, "256-bit token")
}

func TestSession_OtherTenantOrUnknownToken_NotFound(t *testing.T) {
	// Arrange
	svc, _ := newSessionService(time.Hour)
	tenantID := uuid.New()
	token, _, err := svc.CreateSession(context.Background(), tenantID, uuid.New(), "", "")
	require.NoError(t, err)

	// Act
	_, errTenant := svc.GetSession(context.Background(), uuid.New(), token)
	_, errUnknown := svc.GetSession(context.Background(), tenantID, "nope")
	_, errEmpty := svc.GetSession(context.Background(), tenantID, "")

	// Assert
	assert.ErrorIs(t, errTenant, models.ErrSessionNotFound)
	assert.ErrorIs(t, errUnknown, models.ErrSessionNotFound)
	assert.ErrorIs(t, errEmpty, models.ErrSessionNotFound)
}

func TestSession_Expired_NotFoundAndDeleted(t *testing.T) {
	// Arrange
	svc, repo := newSessionService(-time.Second)
	tenantID := uuid.New()
	token, _, err := svc.CreateSession(context.Background(), tenantID, uuid.New(), "", "")
	require.NoError(t, err)

	// Act
	_, getErr := svc.GetSession(context.Background(), tenantID, token)

	// Assert
	assert.ErrorIs(t, getErr, models.ErrSessionNotFound)
	assert.Empty(t, repo.sessions)
}

func TestSession_End_RemovesSession(t *testing.T) {
	// Arrange
	svc, _ := newSessionService(time.Hour)
	tenantID := uuid.New()
	token, _, err := svc.CreateSession(context.Background(), tenantID, uuid.New(), "", "")
	require.NoError(t, err)

	// Act
	require.NoError(t, svc.EndSession(context.Background(), tenantID, token))
	_, getErr := svc.GetSession(context.Background(), tenantID, token)

	// Assert
	assert.ErrorIs(t, getErr, models.ErrSessionNotFound)
}

func TestConsent_GrantAccumulatesAndCoversSubsets(t *testing.T) {
	// Arrange
	svc, _ := newSessionService(time.Hour)
	ctx := context.Background()
	tenantID, userID, clientID := uuid.New(), uuid.New(), uuid.New()

	// Act
	before, _ := svc.HasConsent(ctx, tenantID, userID, clientID, "openid")
	require.NoError(t, svc.GrantConsent(ctx, tenantID, userID, clientID, "openid profile"))
	require.NoError(t, svc.GrantConsent(ctx, tenantID, userID, clientID, "email"))
	all, _ := svc.HasConsent(ctx, tenantID, userID, clientID, "openid profile email")
	subset, _ := svc.HasConsent(ctx, tenantID, userID, clientID, "profile")
	wider, _ := svc.HasConsent(ctx, tenantID, userID, clientID, "openid phone")
	otherClient, _ := svc.HasConsent(ctx, tenantID, userID, uuid.New(), "openid")

	// Assert
	assert.False(t, before)
	assert.True(t, all, "grants accumulate")
	assert.True(t, subset)
	assert.False(t, wider)
	assert.False(t, otherClient)
}

func TestSession_CleanupExpired_RemovesOnlyExpired(t *testing.T) {
	// Arrange
	svc, repo := newSessionService(time.Hour)
	ctx := context.Background()
	tenantID := uuid.New()
	_, _, err := svc.CreateSession(ctx, tenantID, uuid.New(), "", "")
	require.NoError(t, err)
	_, expired, err := svc.CreateSession(ctx, tenantID, uuid.New(), "", "")
	require.NoError(t, err)
	repo.sessions[expired.TokenHash].ExpiresAt = time.Now().Add(-time.Minute)

	// Act
	cleanupErr := svc.CleanupExpiredSessions(ctx)

	// Assert
	require.NoError(t, cleanupErr)
	assert.Equal(t, 1, repo.count())
	assert.NotContains(t, repo.sessions, expired.TokenHash)
}
