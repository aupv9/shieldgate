package services

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"shieldgate/internal/models"
	"shieldgate/internal/repo"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

const apiKeyScheme = "sg"

type apiKeyServiceImpl struct {
	repos  *repo.Repositories
	logger *logrus.Logger
}

// NewAPIKeyService returns a new APIKeyService.
func NewAPIKeyService(repos *repo.Repositories, logger *logrus.Logger) APIKeyService {
	return &apiKeyServiceImpl{repos: repos, logger: logger}
}

// Create generates a new API key in the format sg_<prefix>_<secret>, stores a SHA-256 hash, and
// returns the full plaintext key once — it is never retrievable again.
func (s *apiKeyServiceImpl) Create(ctx context.Context, tenantID uuid.UUID, userID *uuid.UUID, req *models.CreateAPIKeyRequest) (*models.APIKeyCreateResponse, error) {
	prefixBytes := make([]byte, 4)
	if _, err := rand.Read(prefixBytes); err != nil {
		return nil, fmt.Errorf("generate key prefix: %w", err)
	}
	secretBytes := make([]byte, 16)
	if _, err := rand.Read(secretBytes); err != nil {
		return nil, fmt.Errorf("generate key secret: %w", err)
	}
	prefix := hex.EncodeToString(prefixBytes)
	secret := hex.EncodeToString(secretBytes)
	rawKey := fmt.Sprintf("%s_%s_%s", apiKeyScheme, prefix, secret)
	lastFour := rawKey[len(rawKey)-4:]

	h := sha256.Sum256([]byte(rawKey))
	keyHash := hex.EncodeToString(h[:])

	scopes := req.Scopes
	if scopes == nil {
		scopes = []string{}
	}

	key := &models.APIKey{
		ID:        uuid.New(),
		TenantID:  tenantID,
		UserID:    userID,
		Name:      req.Name,
		KeyHash:   keyHash,
		LastFour:  lastFour,
		Prefix:    prefix,
		Scopes:    scopes,
		ExpiresAt: req.ExpiresAt,
	}
	if err := s.repos.APIKey.Create(ctx, key); err != nil {
		return nil, fmt.Errorf("create API key: %w", err)
	}

	return &models.APIKeyCreateResponse{
		ID:        key.ID,
		TenantID:  key.TenantID,
		UserID:    key.UserID,
		Name:      key.Name,
		Key:       rawKey,
		LastFour:  key.LastFour,
		Prefix:    key.Prefix,
		Scopes:    key.Scopes,
		ExpiresAt: key.ExpiresAt,
		CreatedAt: key.CreatedAt,
	}, nil
}

func (s *apiKeyServiceImpl) GetByID(ctx context.Context, tenantID, keyID uuid.UUID) (*models.APIKey, error) {
	return s.repos.APIKey.GetByID(ctx, tenantID, keyID)
}

func (s *apiKeyServiceImpl) List(ctx context.Context, tenantID uuid.UUID, userID *uuid.UUID, limit, offset int) (*models.PaginatedResponse, error) {
	keys, total, err := s.repos.APIKey.List(ctx, tenantID, userID, limit, offset)
	if err != nil {
		return nil, err
	}
	items := make([]interface{}, len(keys))
	for i, k := range keys {
		items[i] = k
	}
	return models.NewPaginatedResponse(items, limit, offset, total), nil
}

func (s *apiKeyServiceImpl) Revoke(ctx context.Context, tenantID, keyID uuid.UUID) error {
	return s.repos.APIKey.Revoke(ctx, tenantID, keyID)
}

func (s *apiKeyServiceImpl) Delete(ctx context.Context, tenantID, keyID uuid.UUID) error {
	return s.repos.APIKey.Delete(ctx, tenantID, keyID)
}

// Validate hashes the provided raw key, looks it up, and checks revocation/expiry.
// It also updates last_used_at on success.
func (s *apiKeyServiceImpl) Validate(ctx context.Context, rawKey string) (*models.APIKey, error) {
	h := sha256.Sum256([]byte(rawKey))
	keyHash := hex.EncodeToString(h[:])
	key, err := s.repos.APIKey.GetByHash(ctx, keyHash)
	if err != nil {
		return nil, models.ErrAPIKeyNotFound
	}
	if key.IsRevoked() {
		return nil, models.ErrAPIKeyRevoked
	}
	if key.IsExpired() {
		return nil, models.ErrAPIKeyExpired
	}
	now := time.Now()
	key.LastUsedAt = &now
	_ = s.repos.APIKey.UpdateLastUsed(ctx, key.ID)
	return key, nil
}
