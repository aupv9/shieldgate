package tests

import (
	"context"
	"testing"
	"time"

	"shieldgate/internal/models"
	"shieldgate/internal/repo"
	"shieldgate/internal/services"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// ── in-memory consent repo ────────────────────────────────────────────────────

type memConsentRepo struct {
	records map[string]*models.ConsentRecord
}

func newMemConsentRepo() *memConsentRepo {
	return &memConsentRepo{records: make(map[string]*models.ConsentRecord)}
}

func consentKey(tenantID, userID, clientID uuid.UUID) string {
	return tenantID.String() + "|" + userID.String() + "|" + clientID.String()
}

func (r *memConsentRepo) Upsert(_ context.Context, c *models.ConsentRecord) error {
	k := consentKey(c.TenantID, c.UserID, c.ClientID)
	if existing, ok := r.records[k]; ok {
		existing.Scopes = c.Scopes
		existing.ExpiresAt = c.ExpiresAt
		existing.UpdatedAt = time.Now()
		return nil
	}
	c.ID = uuid.New()
	c.CreatedAt = time.Now()
	c.UpdatedAt = time.Now()
	r.records[k] = c
	return nil
}

func (r *memConsentRepo) GetByUserAndClient(_ context.Context, tenantID, userID, clientID uuid.UUID) (*models.ConsentRecord, error) {
	k := consentKey(tenantID, userID, clientID)
	c, ok := r.records[k]
	if !ok {
		return nil, gorm.ErrRecordNotFound
	}
	return c, nil
}

func (r *memConsentRepo) ListByUser(_ context.Context, tenantID, userID uuid.UUID) ([]*models.ConsentRecord, error) {
	var out []*models.ConsentRecord
	for _, c := range r.records {
		if c.TenantID == tenantID && c.UserID == userID {
			out = append(out, c)
		}
	}
	return out, nil
}

func (r *memConsentRepo) Delete(_ context.Context, tenantID, userID, clientID uuid.UUID) error {
	k := consentKey(tenantID, userID, clientID)
	if _, ok := r.records[k]; !ok {
		return gorm.ErrRecordNotFound
	}
	delete(r.records, k)
	return nil
}

func (r *memConsentRepo) DeleteExpired(_ context.Context) error {
	now := time.Now()
	for k, c := range r.records {
		if c.ExpiresAt != nil && now.After(*c.ExpiresAt) {
			delete(r.records, k)
		}
	}
	return nil
}

// ── in-memory blocklist repo ──────────────────────────────────────────────────

type memBlocklistRepo struct {
	entries map[string]*models.TokenBlocklist
}

func newMemBlocklistRepo() *memBlocklistRepo {
	return &memBlocklistRepo{entries: make(map[string]*models.TokenBlocklist)}
}

func (r *memBlocklistRepo) Add(_ context.Context, e *models.TokenBlocklist) error {
	r.entries[e.JTI] = e
	return nil
}

func (r *memBlocklistRepo) IsBlocked(_ context.Context, jti string) (bool, error) {
	e, ok := r.entries[jti]
	if !ok {
		return false, nil
	}
	return time.Now().Before(e.ExpiresAt), nil
}

func (r *memBlocklistRepo) DeleteExpired(_ context.Context) error {
	now := time.Now()
	for k, e := range r.entries {
		if now.After(e.ExpiresAt) {
			delete(r.entries, k)
		}
	}
	return nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

func newConsentRepos() *repo.Repositories {
	return &repo.Repositories{
		Consent:   newMemConsentRepo(),
		Blocklist: newMemBlocklistRepo(),
	}
}

func newConsentSvc(repos *repo.Repositories) services.ConsentService {
	return services.NewConsentService(repos, logrus.New())
}

func newBlocklistSvc(repos *repo.Repositories) services.BlocklistService {
	return services.NewBlocklistService(repos, logrus.New())
}

// ── ConsentService tests ──────────────────────────────────────────────────────

func TestConsentService_GrantAndCheck_AllScopes(t *testing.T) {
	repos := newConsentRepos()
	svc := newConsentSvc(repos)

	tenantID := uuid.New()
	userID := uuid.New()
	clientID := uuid.New()

	require.NoError(t, svc.GrantConsent(context.Background(), tenantID, userID, clientID, []string{"read", "write"}, nil))

	ok, err := svc.HasConsent(context.Background(), tenantID, userID, clientID, []string{"read", "write"})
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestConsentService_HasConsent_MissingScope(t *testing.T) {
	repos := newConsentRepos()
	svc := newConsentSvc(repos)

	tenantID, userID, clientID := uuid.New(), uuid.New(), uuid.New()
	require.NoError(t, svc.GrantConsent(context.Background(), tenantID, userID, clientID, []string{"read"}, nil))

	ok, err := svc.HasConsent(context.Background(), tenantID, userID, clientID, []string{"read", "admin"})
	require.NoError(t, err)
	assert.False(t, ok, "should be false when requested scope not granted")
}

func TestConsentService_HasConsent_NotFound(t *testing.T) {
	repos := newConsentRepos()
	svc := newConsentSvc(repos)

	ok, err := svc.HasConsent(context.Background(), uuid.New(), uuid.New(), uuid.New(), []string{"read"})
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestConsentService_HasConsent_Expired(t *testing.T) {
	repos := newConsentRepos()
	svc := newConsentSvc(repos)

	tenantID, userID, clientID := uuid.New(), uuid.New(), uuid.New()
	past := time.Now().Add(-1 * time.Hour)
	require.NoError(t, svc.GrantConsent(context.Background(), tenantID, userID, clientID, []string{"read"}, &past))

	ok, err := svc.HasConsent(context.Background(), tenantID, userID, clientID, []string{"read"})
	require.NoError(t, err)
	assert.False(t, ok, "expired consent should not be valid")
}

func TestConsentService_RevokeConsent(t *testing.T) {
	repos := newConsentRepos()
	svc := newConsentSvc(repos)

	tenantID, userID, clientID := uuid.New(), uuid.New(), uuid.New()
	require.NoError(t, svc.GrantConsent(context.Background(), tenantID, userID, clientID, []string{"read"}, nil))
	require.NoError(t, svc.RevokeConsent(context.Background(), tenantID, userID, clientID))

	ok, err := svc.HasConsent(context.Background(), tenantID, userID, clientID, []string{"read"})
	require.NoError(t, err)
	assert.False(t, ok, "revoked consent should not be found")
}

func TestConsentService_ListConsents(t *testing.T) {
	repos := newConsentRepos()
	svc := newConsentSvc(repos)

	tenantID, userID := uuid.New(), uuid.New()
	require.NoError(t, svc.GrantConsent(context.Background(), tenantID, userID, uuid.New(), []string{"read"}, nil))
	require.NoError(t, svc.GrantConsent(context.Background(), tenantID, userID, uuid.New(), []string{"write"}, nil))

	records, err := svc.ListConsents(context.Background(), tenantID, userID)
	require.NoError(t, err)
	assert.Len(t, records, 2)
}

func TestConsentService_Upsert_UpdatesExisting(t *testing.T) {
	repos := newConsentRepos()
	svc := newConsentSvc(repos)

	tenantID, userID, clientID := uuid.New(), uuid.New(), uuid.New()
	require.NoError(t, svc.GrantConsent(context.Background(), tenantID, userID, clientID, []string{"read"}, nil))
	require.NoError(t, svc.GrantConsent(context.Background(), tenantID, userID, clientID, []string{"read", "write"}, nil))

	records, err := svc.ListConsents(context.Background(), tenantID, userID)
	require.NoError(t, err)
	assert.Len(t, records, 1, "upsert should not create duplicate")
	assert.Contains(t, []string(records[0].Scopes), "write")
}

// ── BlocklistService tests ────────────────────────────────────────────────────

func TestBlocklistService_BlockAndCheck(t *testing.T) {
	repos := newConsentRepos()
	svc := newBlocklistSvc(repos)

	tenantID, userID := uuid.New(), uuid.New()
	jti := uuid.New().String()
	expiresAt := time.Now().Add(1 * time.Hour)

	require.NoError(t, svc.Block(context.Background(), jti, tenantID, userID, expiresAt))

	blocked, err := svc.IsBlocked(context.Background(), jti)
	require.NoError(t, err)
	assert.True(t, blocked)
}

func TestBlocklistService_NotBlocked_Unknown(t *testing.T) {
	repos := newConsentRepos()
	svc := newBlocklistSvc(repos)

	blocked, err := svc.IsBlocked(context.Background(), "unknown-jti")
	require.NoError(t, err)
	assert.False(t, blocked)
}

func TestBlocklistService_Expired_NotBlocked(t *testing.T) {
	repos := newConsentRepos()
	svc := newBlocklistSvc(repos)

	tenantID, userID := uuid.New(), uuid.New()
	jti := uuid.New().String()
	past := time.Now().Add(-1 * time.Hour)

	require.NoError(t, svc.Block(context.Background(), jti, tenantID, userID, past))

	blocked, err := svc.IsBlocked(context.Background(), jti)
	require.NoError(t, err)
	assert.False(t, blocked, "expired token should not be reported as blocked")
}

func TestBlocklistService_Cleanup(t *testing.T) {
	repos := newConsentRepos()
	svc := newBlocklistSvc(repos)

	tenantID, userID := uuid.New(), uuid.New()
	past := time.Now().Add(-1 * time.Hour)
	require.NoError(t, svc.Block(context.Background(), "old-jti", tenantID, userID, past))
	require.NoError(t, svc.Cleanup(context.Background()))

	blocked, _ := svc.IsBlocked(context.Background(), "old-jti")
	assert.False(t, blocked)
}
