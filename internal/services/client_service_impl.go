package services

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"shieldgate/internal/models"
	"shieldgate/internal/repo"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

type clientServiceImpl struct {
	repos  *repo.Repositories
	logger *logrus.Logger
}

// NewClientService creates a new client service implementation
func NewClientService(repos *repo.Repositories, logger *logrus.Logger) ClientService {
	return &clientServiceImpl{
		repos:  repos,
		logger: logger,
	}
}

func (s *clientServiceImpl) Create(ctx context.Context, tenantID uuid.UUID, req *models.CreateClientRequest) (*models.Client, error) {
	// Validate request
	if req.Name == "" {
		return nil, fmt.Errorf("client name is required")
	}
	if len(req.RedirectURIs) == 0 {
		return nil, fmt.Errorf("at least one redirect URI is required")
	}
	if len(req.GrantTypes) == 0 {
		return nil, fmt.Errorf("at least one grant type is required")
	}

	// Generate client ID
	clientID := generateClientID()

	// Generate client secret for confidential clients. Only the bcrypt hash is
	// stored; the plaintext is returned exactly once in the create response.
	var plainSecret, secretHash string
	if !req.IsPublic {
		var err error
		plainSecret, err = generateClientSecret()
		if err != nil {
			return nil, fmt.Errorf("failed to generate client secret: %w", err)
		}
		secretHash, err = hashClientSecret(plainSecret)
		if err != nil {
			return nil, fmt.Errorf("failed to hash client secret: %w", err)
		}
	}

	// Create client
	client := &models.Client{
		ID:           uuid.New(),
		TenantID:     tenantID,
		ClientID:     clientID,
		ClientSecret: secretHash,
		Name:         req.Name,
		RedirectURIs: models.StringArray(req.RedirectURIs),
		GrantTypes:   models.StringArray(req.GrantTypes),
		Scopes:       models.StringArray(req.Scopes),
		IsPublic:     req.IsPublic,
	}

	if err := s.repos.Client.Create(ctx, client); err != nil {
		s.logger.WithError(err).Error("failed to create client")
		return nil, fmt.Errorf("failed to create client: %w", err)
	}

	client.PlainClientSecret = plainSecret

	s.logger.WithFields(logrus.Fields{
		"tenant_id": tenantID,
		"client_id": client.ClientID,
		"name":      client.Name,
		"is_public": client.IsPublic,
	}).Info("client created successfully")

	return client, nil
}

func (s *clientServiceImpl) GetByID(ctx context.Context, tenantID, clientID uuid.UUID) (*models.Client, error) {
	client, err := s.repos.Client.GetByID(ctx, tenantID, clientID)
	if err != nil {
		s.logger.WithError(err).WithFields(logrus.Fields{
			"tenant_id": tenantID,
			"client_id": clientID,
		}).Error("failed to get client by ID")
		return nil, err
	}
	return client, nil
}

func (s *clientServiceImpl) GetByClientID(ctx context.Context, tenantID uuid.UUID, clientID string) (*models.Client, error) {
	client, err := s.repos.Client.GetByClientID(ctx, tenantID, clientID)
	if err != nil {
		s.logger.WithError(err).WithFields(logrus.Fields{
			"tenant_id": tenantID,
			"client_id": clientID,
		}).Error("failed to get client by client_id")
		return nil, err
	}
	return client, nil
}

func (s *clientServiceImpl) Update(ctx context.Context, tenantID, clientID uuid.UUID, req *models.UpdateClientRequest) (*models.Client, error) {
	// Get existing client
	client, err := s.repos.Client.GetByID(ctx, tenantID, clientID)
	if err != nil {
		return nil, err
	}

	// Update fields
	if req.Name != "" {
		client.Name = req.Name
	}
	if len(req.RedirectURIs) > 0 {
		client.RedirectURIs = models.StringArray(req.RedirectURIs)
	}
	if len(req.GrantTypes) > 0 {
		client.GrantTypes = models.StringArray(req.GrantTypes)
	}
	if len(req.Scopes) > 0 {
		client.Scopes = models.StringArray(req.Scopes)
	}
	var plainSecret string
	if req.IsPublic != nil {
		client.IsPublic = *req.IsPublic
		// If changing to confidential client, generate secret
		if !*req.IsPublic && client.ClientSecret == "" {
			var err error
			plainSecret, err = generateClientSecret()
			if err != nil {
				return nil, fmt.Errorf("failed to generate client secret: %w", err)
			}
			client.ClientSecret, err = hashClientSecret(plainSecret)
			if err != nil {
				return nil, fmt.Errorf("failed to hash client secret: %w", err)
			}
		}
		// If changing to public client, clear secret
		if *req.IsPublic {
			client.ClientSecret = ""
		}
	}

	if err := s.repos.Client.Update(ctx, client); err != nil {
		s.logger.WithError(err).WithField("client_id", clientID).Error("failed to update client")
		return nil, fmt.Errorf("failed to update client: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"tenant_id": tenantID,
		"client_id": client.ClientID,
		"name":      client.Name,
	}).Info("client updated successfully")

	client.PlainClientSecret = plainSecret
	return client, nil
}

func (s *clientServiceImpl) Delete(ctx context.Context, tenantID, clientID uuid.UUID) error {
	// Check if client exists
	if _, err := s.repos.Client.GetByID(ctx, tenantID, clientID); err != nil {
		return err
	}

	if err := s.repos.Client.Delete(ctx, tenantID, clientID); err != nil {
		s.logger.WithError(err).WithField("client_id", clientID).Error("failed to delete client")
		return fmt.Errorf("failed to delete client: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"tenant_id": tenantID,
		"client_id": clientID,
	}).Info("client deleted successfully")

	return nil
}

func (s *clientServiceImpl) List(ctx context.Context, tenantID uuid.UUID, limit, offset int) (*models.PaginatedResponse, error) {
	// Validate pagination parameters
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	if offset < 0 {
		offset = 0
	}

	clients, total, err := s.repos.Client.List(ctx, tenantID, limit, offset)
	if err != nil {
		s.logger.WithError(err).WithField("tenant_id", tenantID).Error("failed to list clients")
		return nil, fmt.Errorf("failed to list clients: %w", err)
	}

	return models.NewPaginatedResponse(
		models.ClientsToInterface(clients),
		limit,
		offset,
		total,
	), nil
}

func (s *clientServiceImpl) ValidateClient(ctx context.Context, tenantID uuid.UUID, clientID, clientSecret string) (*models.Client, error) {
	// Get client
	client, err := s.repos.Client.GetByClientID(ctx, tenantID, clientID)
	if err != nil {
		return nil, models.ErrInvalidClient
	}

	// For public clients, no secret validation needed
	if client.IsPublic {
		if clientSecret != "" {
			return nil, models.ErrInvalidClient
		}
		return client, nil
	}

	// For confidential clients, validate secret against the stored bcrypt hash
	if clientSecret == "" || client.ClientSecret == "" ||
		bcrypt.CompareHashAndPassword([]byte(client.ClientSecret), []byte(clientSecret)) != nil {
		s.logger.WithFields(logrus.Fields{
			"tenant_id": tenantID,
			"client_id": clientID,
		}).Warn("client secret validation failed")
		return nil, models.ErrInvalidClient
	}

	return client, nil
}

func (s *clientServiceImpl) ValidateRedirectURI(ctx context.Context, client *models.Client, redirectURI string) error {
	// Check if redirect URI is in the allowed list
	for _, allowedURI := range client.RedirectURIs {
		if allowedURI == redirectURI {
			return nil
		}
	}

	s.logger.WithFields(logrus.Fields{
		"client_id":    client.ClientID,
		"redirect_uri": redirectURI,
		"allowed_uris": client.RedirectURIs,
	}).Warn("redirect URI validation failed")

	return fmt.Errorf("redirect URI not allowed")
}

// Helper functions

func generateClientID() string {
	// Generate a client ID with prefix
	return "client_" + uuid.New().String()[:16]
}

// generateClientSecret returns a 256-bit random secret (base64url-encoded)
func generateClientSecret() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return "secret_" + base64.RawURLEncoding.EncodeToString(bytes), nil
}

func hashClientSecret(secret string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}
