package services

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"shield1/internal/models"
)

// ClientService handles OAuth client management
type ClientService struct {
	db *gorm.DB
}

// NewClientService creates a new ClientService instance
func NewClientService(db *gorm.DB) *ClientService {
	return &ClientService{
		db: db,
	}
}

// CreateClient creates a new OAuth client
func (s *ClientService) CreateClient(req *models.CreateClientRequest) (*models.Client, error) {
	// Generate client ID
	clientID, err := s.generateClientID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate client ID: %w", err)
	}

	// Generate client secret for confidential clients
	var clientSecret string
	if !req.IsPublic {
		clientSecret, err = s.generateClientSecret()
		if err != nil {
			return nil, fmt.Errorf("failed to generate client secret: %w", err)
		}
	}

	client := &models.Client{
		ID:           uuid.New(),
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Name:         req.Name,
		RedirectURIs: models.StringArray(req.RedirectURIs),
		GrantTypes:   models.StringArray(req.GrantTypes),
		Scopes:       models.StringArray(req.Scopes),
		IsPublic:     req.IsPublic,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	// Store in database using GORM
	if err := s.db.Create(client).Error; err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}

	logrus.Infof("Created new client: %s (%s)", client.Name, client.ClientID)
	return client, nil
}

// GetClient retrieves a client by client ID
func (s *ClientService) GetClient(clientID string) (*models.Client, error) {
	var client models.Client
	err := s.db.Where("client_id = ?", clientID).First(&client).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("client not found")
		}
		return nil, fmt.Errorf("failed to get client: %w", err)
	}

	return &client, nil
}

// GetClientByID retrieves a client by internal ID
func (s *ClientService) GetClientByID(id uuid.UUID) (*models.Client, error) {
	var client models.Client
	err := s.db.Where("id = ?", id).First(&client).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("client not found")
		}
		return nil, fmt.Errorf("failed to get client: %w", err)
	}

	return &client, nil
}

// UpdateClient updates an existing client
func (s *ClientService) UpdateClient(clientID string, req *models.UpdateClientRequest) (*models.Client, error) {
	// Get existing client
	client, err := s.GetClient(clientID)
	if err != nil {
		return nil, err
	}

	// Update fields if provided
	if req.Name != "" {
		client.Name = req.Name
	}
	if req.RedirectURIs != nil {
		client.RedirectURIs = models.StringArray(req.RedirectURIs)
	}
	if req.GrantTypes != nil {
		client.GrantTypes = models.StringArray(req.GrantTypes)
	}
	if req.Scopes != nil {
		client.Scopes = models.StringArray(req.Scopes)
	}
	if req.IsPublic != nil {
		client.IsPublic = *req.IsPublic
		// If changing to public, clear client secret
		if *req.IsPublic {
			client.ClientSecret = ""
		} else if client.ClientSecret == "" {
			// If changing to confidential and no secret exists, generate one
			clientSecret, err := s.generateClientSecret()
			if err != nil {
				return nil, fmt.Errorf("failed to generate client secret: %w", err)
			}
			client.ClientSecret = clientSecret
		}
	}

	client.UpdatedAt = time.Now()

	// Save changes using GORM
	if err := s.db.Save(client).Error; err != nil {
		return nil, fmt.Errorf("failed to update client: %w", err)
	}

	logrus.Infof("Updated client: %s (%s)", client.Name, client.ClientID)
	return client, nil
}

// DeleteClient deletes a client
func (s *ClientService) DeleteClient(clientID string) error {
	result := s.db.Where("client_id = ?", clientID).Delete(&models.Client{})
	if result.Error != nil {
		return fmt.Errorf("failed to delete client: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return fmt.Errorf("client not found")
	}

	logrus.Infof("Deleted client: %s", clientID)
	return nil
}

// ListClients retrieves all clients with pagination
func (s *ClientService) ListClients(limit, offset int) ([]*models.Client, int, error) {
	var total int64
	var clients []*models.Client

	// Get total count
	if err := s.db.Model(&models.Client{}).Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to get client count: %w", err)
	}

	// Get clients with pagination
	err := s.db.Order("created_at DESC").Limit(limit).Offset(offset).Find(&clients).Error
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list clients: %w", err)
	}

	// Don't expose client secret in list
	for _, client := range clients {
		client.ClientSecret = ""
	}

	return clients, int(total), nil
}

// ValidateClient validates client credentials
func (s *ClientService) ValidateClient(clientID, clientSecret string) (*models.Client, error) {
	client, err := s.GetClient(clientID)
	if err != nil {
		return nil, fmt.Errorf("invalid client")
	}

	// For public clients, no secret validation needed
	if client.IsPublic {
		if clientSecret != "" {
			return nil, fmt.Errorf("public client should not have secret")
		}
		return client, nil
	}

	// For confidential clients, validate secret
	if clientSecret == "" {
		return nil, fmt.Errorf("client secret required")
	}

	// Compare client secret (assuming it's hashed)
	err = bcrypt.CompareHashAndPassword([]byte(client.ClientSecret), []byte(clientSecret))
	if err != nil {
		return nil, fmt.Errorf("invalid client credentials")
	}

	return client, nil
}

// ValidateRedirectURI validates if the redirect URI is allowed for the client
func (s *ClientService) ValidateRedirectURI(clientID, redirectURI string) error {
	client, err := s.GetClient(clientID)
	if err != nil {
		return err
	}

	if !client.HasRedirectURI(redirectURI) {
		return fmt.Errorf("invalid redirect URI")
	}

	return nil
}

// Helper methods

func (s *ClientService) generateClientID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes)[:22], nil // Remove padding
}

func (s *ClientService) generateClientSecret() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	// Hash the secret before storing
	secret := base64.URLEncoding.EncodeToString(bytes)
	hashedSecret, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(hashedSecret), nil
}
