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

// --- in-memory Webhook repo ---

type memWebhookRepo struct {
	endpoints map[uuid.UUID]*models.WebhookEndpoint
	deliveries []*models.WebhookDelivery
}

func newMemWebhookRepo() *memWebhookRepo {
	return &memWebhookRepo{
		endpoints:  make(map[uuid.UUID]*models.WebhookEndpoint),
		deliveries: []*models.WebhookDelivery{},
	}
}

func (r *memWebhookRepo) Create(_ context.Context, w *models.WebhookEndpoint) error {
	r.endpoints[w.ID] = w
	return nil
}

func (r *memWebhookRepo) GetByID(_ context.Context, tenantID, id uuid.UUID) (*models.WebhookEndpoint, error) {
	w, ok := r.endpoints[id]
	if !ok || w.TenantID != tenantID {
		return nil, models.ErrWebhookNotFound
	}
	return w, nil
}

func (r *memWebhookRepo) Update(_ context.Context, w *models.WebhookEndpoint) error {
	r.endpoints[w.ID] = w
	return nil
}

func (r *memWebhookRepo) Delete(_ context.Context, tenantID, id uuid.UUID) error {
	if w, ok := r.endpoints[id]; ok && w.TenantID == tenantID {
		delete(r.endpoints, id)
		return nil
	}
	return models.ErrWebhookNotFound
}

func (r *memWebhookRepo) List(_ context.Context, tenantID uuid.UUID, limit, offset int) ([]*models.WebhookEndpoint, int64, error) {
	var out []*models.WebhookEndpoint
	for _, w := range r.endpoints {
		if w.TenantID == tenantID {
			out = append(out, w)
		}
	}
	total := int64(len(out))
	if offset >= len(out) {
		return []*models.WebhookEndpoint{}, total, nil
	}
	end := offset + limit
	if end > len(out) {
		end = len(out)
	}
	return out[offset:end], total, nil
}

func (r *memWebhookRepo) ListActive(_ context.Context, tenantID uuid.UUID, event string) ([]*models.WebhookEndpoint, error) {
	var out []*models.WebhookEndpoint
	for _, w := range r.endpoints {
		if w.TenantID != tenantID || !w.IsActive {
			continue
		}
		for _, e := range w.Events {
			if e == event || e == "*" {
				out = append(out, w)
				break
			}
		}
	}
	return out, nil
}

func (r *memWebhookRepo) CreateDelivery(_ context.Context, d *models.WebhookDelivery) error {
	r.deliveries = append(r.deliveries, d)
	return nil
}

func (r *memWebhookRepo) ListDeliveries(_ context.Context, tenantID, webhookID uuid.UUID, limit, offset int) ([]*models.WebhookDelivery, int64, error) {
	var out []*models.WebhookDelivery
	for _, d := range r.deliveries {
		if d.TenantID == tenantID && d.WebhookID == webhookID {
			out = append(out, d)
		}
	}
	return out, int64(len(out)), nil
}

// --- tests ---

func TestWebhookEndpoint_CreateAndGet(t *testing.T) {
	repo := newMemWebhookRepo()
	tenantID := uuid.New()
	w := &models.WebhookEndpoint{
		ID:       uuid.New(),
		TenantID: tenantID,
		URL:      "https://example.com/hook",
		Secret:   "s3cr3t",
		Events:   models.StringArray{"user.created"},
		IsActive: true,
	}
	require.NoError(t, repo.Create(context.Background(), w))

	got, err := repo.GetByID(context.Background(), tenantID, w.ID)
	require.NoError(t, err)
	assert.Equal(t, "https://example.com/hook", got.URL)
}

func TestWebhookEndpoint_GetNotFound(t *testing.T) {
	repo := newMemWebhookRepo()
	_, err := repo.GetByID(context.Background(), uuid.New(), uuid.New())
	assert.ErrorIs(t, err, models.ErrWebhookNotFound)
}

func TestWebhookEndpoint_Update(t *testing.T) {
	repo := newMemWebhookRepo()
	tenantID := uuid.New()
	w := &models.WebhookEndpoint{
		ID: uuid.New(), TenantID: tenantID,
		URL: "https://old.example.com", Secret: "s", IsActive: true,
	}
	_ = repo.Create(context.Background(), w)
	w.URL = "https://new.example.com"
	require.NoError(t, repo.Update(context.Background(), w))
	got, _ := repo.GetByID(context.Background(), tenantID, w.ID)
	assert.Equal(t, "https://new.example.com", got.URL)
}

func TestWebhookEndpoint_Delete(t *testing.T) {
	repo := newMemWebhookRepo()
	tenantID := uuid.New()
	w := &models.WebhookEndpoint{ID: uuid.New(), TenantID: tenantID, IsActive: true}
	_ = repo.Create(context.Background(), w)
	require.NoError(t, repo.Delete(context.Background(), tenantID, w.ID))
	_, err := repo.GetByID(context.Background(), tenantID, w.ID)
	assert.ErrorIs(t, err, models.ErrWebhookNotFound)
}

func TestWebhookEndpoint_ListActive_MatchesEvent(t *testing.T) {
	repo := newMemWebhookRepo()
	tenantID := uuid.New()
	_ = repo.Create(context.Background(), &models.WebhookEndpoint{
		ID: uuid.New(), TenantID: tenantID, IsActive: true,
		Events: models.StringArray{"user.created", "user.deleted"},
	})
	_ = repo.Create(context.Background(), &models.WebhookEndpoint{
		ID: uuid.New(), TenantID: tenantID, IsActive: true,
		Events: models.StringArray{"token.issued"},
	})
	active, err := repo.ListActive(context.Background(), tenantID, "user.created")
	require.NoError(t, err)
	assert.Len(t, active, 1)
}

func TestWebhookEndpoint_ListActive_SkipsInactive(t *testing.T) {
	repo := newMemWebhookRepo()
	tenantID := uuid.New()
	_ = repo.Create(context.Background(), &models.WebhookEndpoint{
		ID: uuid.New(), TenantID: tenantID, IsActive: false,
		Events: models.StringArray{"user.created"},
	})
	active, _ := repo.ListActive(context.Background(), tenantID, "user.created")
	assert.Empty(t, active)
}

func TestWebhookDelivery_CreateAndList(t *testing.T) {
	repo := newMemWebhookRepo()
	tenantID := uuid.New()
	webhookID := uuid.New()
	now := time.Now()
	_ = repo.CreateDelivery(context.Background(), &models.WebhookDelivery{
		ID: uuid.New(), WebhookID: webhookID, TenantID: tenantID,
		Event: "user.created", Success: true, DeliveredAt: &now,
	})
	deliveries, total, err := repo.ListDeliveries(context.Background(), tenantID, webhookID, 10, 0)
	require.NoError(t, err)
	assert.Equal(t, int64(1), total)
	assert.Len(t, deliveries, 1)
	assert.True(t, deliveries[0].Success)
}

func TestWebhookEndpoint_List_Pagination(t *testing.T) {
	repo := newMemWebhookRepo()
	tenantID := uuid.New()
	for i := 0; i < 5; i++ {
		_ = repo.Create(context.Background(), &models.WebhookEndpoint{
			ID: uuid.New(), TenantID: tenantID, IsActive: true,
		})
	}
	page, total, err := repo.List(context.Background(), tenantID, 3, 0)
	require.NoError(t, err)
	assert.Equal(t, int64(5), total)
	assert.Len(t, page, 3)
}

func TestWebhookEndpoint_TenantIsolation(t *testing.T) {
	repo := newMemWebhookRepo()
	t1, t2 := uuid.New(), uuid.New()
	_ = repo.Create(context.Background(), &models.WebhookEndpoint{ID: uuid.New(), TenantID: t1, IsActive: true})
	_ = repo.Create(context.Background(), &models.WebhookEndpoint{ID: uuid.New(), TenantID: t2, IsActive: true})
	list, total, _ := repo.List(context.Background(), t1, 10, 0)
	assert.Equal(t, int64(1), total)
	assert.Len(t, list, 1)
}
