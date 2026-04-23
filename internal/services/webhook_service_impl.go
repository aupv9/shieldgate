package services

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"shieldgate/internal/models"
	"shieldgate/internal/repo"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type webhookServiceImpl struct {
	repos      *repo.Repositories
	httpClient *http.Client
	logger     *logrus.Logger
}

// NewWebhookService returns a new WebhookService.
func NewWebhookService(repos *repo.Repositories, logger *logrus.Logger) WebhookService {
	return &webhookServiceImpl{
		repos:      repos,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		logger:     logger,
	}
}

func (s *webhookServiceImpl) Create(ctx context.Context, tenantID uuid.UUID, req *models.CreateWebhookRequest) (*models.WebhookEndpoint, error) {
	secret := req.Secret
	if secret == "" {
		b := make([]byte, 20)
		if _, err := rand.Read(b); err != nil {
			return nil, fmt.Errorf("generate webhook secret: %w", err)
		}
		secret = hex.EncodeToString(b)
	}
	w := &models.WebhookEndpoint{
		ID:          uuid.New(),
		TenantID:    tenantID,
		URL:         req.URL,
		Secret:      secret,
		Events:      req.Events,
		Description: req.Description,
		IsActive:    true,
	}
	if err := s.repos.Webhook.Create(ctx, w); err != nil {
		return nil, fmt.Errorf("create webhook: %w", err)
	}
	return w, nil
}

func (s *webhookServiceImpl) GetByID(ctx context.Context, tenantID, webhookID uuid.UUID) (*models.WebhookEndpoint, error) {
	return s.repos.Webhook.GetByID(ctx, tenantID, webhookID)
}

func (s *webhookServiceImpl) Update(ctx context.Context, tenantID, webhookID uuid.UUID, req *models.UpdateWebhookRequest) (*models.WebhookEndpoint, error) {
	w, err := s.repos.Webhook.GetByID(ctx, tenantID, webhookID)
	if err != nil {
		return nil, models.ErrWebhookNotFound
	}
	if req.URL != "" {
		w.URL = req.URL
	}
	if req.Events != nil {
		w.Events = req.Events
	}
	if req.Description != "" {
		w.Description = req.Description
	}
	if req.IsActive != nil {
		w.IsActive = *req.IsActive
	}
	if err := s.repos.Webhook.Update(ctx, w); err != nil {
		return nil, fmt.Errorf("update webhook: %w", err)
	}
	return w, nil
}

func (s *webhookServiceImpl) Delete(ctx context.Context, tenantID, webhookID uuid.UUID) error {
	return s.repos.Webhook.Delete(ctx, tenantID, webhookID)
}

func (s *webhookServiceImpl) List(ctx context.Context, tenantID uuid.UUID, limit, offset int) (*models.PaginatedResponse, error) {
	webhooks, total, err := s.repos.Webhook.List(ctx, tenantID, limit, offset)
	if err != nil {
		return nil, err
	}
	items := make([]interface{}, len(webhooks))
	for i, w := range webhooks {
		items[i] = w
	}
	return models.NewPaginatedResponse(items, limit, offset, total), nil
}

// Dispatch fans out an event to all active matching webhook endpoints (non-blocking).
func (s *webhookServiceImpl) Dispatch(ctx context.Context, tenantID uuid.UUID, event string, payload interface{}) error {
	endpoints, err := s.repos.Webhook.ListActive(ctx, tenantID, event)
	if err != nil {
		return err
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal webhook payload: %w", err)
	}
	for _, ep := range endpoints {
		go s.deliver(context.Background(), tenantID, ep, event, body)
	}
	return nil
}

func (s *webhookServiceImpl) deliver(ctx context.Context, tenantID uuid.UUID, ep *models.WebhookEndpoint, event string, body []byte) {
	delivery := &models.WebhookDelivery{
		ID:        uuid.New(),
		WebhookID: ep.ID,
		TenantID:  tenantID,
		Event:     event,
		Payload:   string(body),
		Attempt:   1,
	}

	sig := s.sign(ep.Secret, body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.URL, bytes.NewReader(body))
	if err != nil {
		delivery.ErrorMessage = err.Error()
		_ = s.repos.Webhook.CreateDelivery(ctx, delivery)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-ShieldGate-Event", event)
	req.Header.Set("X-ShieldGate-Signature", "sha256="+sig)
	req.Header.Set("X-ShieldGate-Delivery", delivery.ID.String())

	resp, err := s.httpClient.Do(req)
	if err != nil {
		delivery.ErrorMessage = err.Error()
		_ = s.repos.Webhook.CreateDelivery(ctx, delivery)
		return
	}
	defer resp.Body.Close()

	now := time.Now()
	delivery.StatusCode = resp.StatusCode
	delivery.Success = resp.StatusCode >= 200 && resp.StatusCode < 300
	delivery.DeliveredAt = &now
	if err := s.repos.Webhook.CreateDelivery(ctx, delivery); err != nil {
		s.logger.WithError(err).Warn("failed to record webhook delivery")
	}
}

func (s *webhookServiceImpl) sign(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *webhookServiceImpl) ListDeliveries(ctx context.Context, tenantID, webhookID uuid.UUID, limit, offset int) (*models.PaginatedResponse, error) {
	deliveries, total, err := s.repos.Webhook.ListDeliveries(ctx, tenantID, webhookID, limit, offset)
	if err != nil {
		return nil, err
	}
	items := make([]interface{}, len(deliveries))
	for i, d := range deliveries {
		items[i] = d
	}
	return models.NewPaginatedResponse(items, limit, offset, total), nil
}
