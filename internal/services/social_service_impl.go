package services

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"shieldgate/internal/models"
	"shieldgate/internal/repo"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type socialLoginServiceImpl struct {
	repos  *repo.Repositories
	logger *logrus.Logger
}

// NewSocialLoginService returns a new SocialLoginService.
func NewSocialLoginService(repos *repo.Repositories, logger *logrus.Logger) SocialLoginService {
	return &socialLoginServiceImpl{repos: repos, logger: logger}
}

func (s *socialLoginServiceImpl) ConfigureProvider(ctx context.Context, tenantID uuid.UUID, provider, clientID, clientSecret string, scopes []string) (*models.SocialProvider, error) {
	if scopes == nil {
		scopes = []string{}
	}
	p := &models.SocialProvider{
		ID:           uuid.New(),
		TenantID:     tenantID,
		Provider:     provider,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       scopes,
		IsActive:     true,
	}
	if err := s.repos.SocialProvider.Create(ctx, p); err != nil {
		return nil, fmt.Errorf("configure provider: %w", err)
	}
	return p, nil
}

func (s *socialLoginServiceImpl) GetProvider(ctx context.Context, tenantID uuid.UUID, provider string) (*models.SocialProvider, error) {
	return s.repos.SocialProvider.GetByTenantAndProvider(ctx, tenantID, provider)
}

func (s *socialLoginServiceImpl) ListProviders(ctx context.Context, tenantID uuid.UUID) ([]*models.SocialProvider, error) {
	return s.repos.SocialProvider.List(ctx, tenantID)
}

func (s *socialLoginServiceImpl) UpdateProvider(ctx context.Context, tenantID uuid.UUID, provider, clientID, clientSecret string, scopes []string, isActive bool) (*models.SocialProvider, error) {
	p, err := s.repos.SocialProvider.GetByTenantAndProvider(ctx, tenantID, provider)
	if err != nil {
		return nil, models.ErrSocialProviderNotConfigured
	}
	if clientID != "" {
		p.ClientID = clientID
	}
	if clientSecret != "" {
		p.ClientSecret = clientSecret
	}
	if scopes != nil {
		p.Scopes = scopes
	}
	p.IsActive = isActive
	if err := s.repos.SocialProvider.Update(ctx, p); err != nil {
		return nil, fmt.Errorf("update provider: %w", err)
	}
	return p, nil
}

func (s *socialLoginServiceImpl) DeleteProvider(ctx context.Context, tenantID uuid.UUID, provider string) error {
	return s.repos.SocialProvider.Delete(ctx, tenantID, provider)
}

func (s *socialLoginServiceImpl) LinkAccount(ctx context.Context, tenantID, userID uuid.UUID, account *models.SocialAccount) error {
	account.ID = uuid.New()
	account.TenantID = tenantID
	account.UserID = userID
	return s.repos.SocialAccount.Create(ctx, account)
}

func (s *socialLoginServiceImpl) UnlinkAccount(ctx context.Context, tenantID, userID uuid.UUID, provider string) error {
	return s.repos.SocialAccount.Delete(ctx, tenantID, userID, provider)
}

func (s *socialLoginServiceImpl) ListLinkedAccounts(ctx context.Context, tenantID, userID uuid.UUID) ([]*models.SocialAccount, error) {
	return s.repos.SocialAccount.ListByUser(ctx, tenantID, userID)
}

func (s *socialLoginServiceImpl) FindOrCreateUser(ctx context.Context, tenantID uuid.UUID, account *models.SocialAccount) (*models.User, error) {
	// If this social identity is already linked, return the existing user.
	existing, err := s.repos.SocialAccount.GetByProviderAndExternalID(ctx, account.Provider, account.ExternalID)
	if err == nil {
		return s.repos.User.GetByID(ctx, existing.TenantID, existing.UserID)
	}

	// Try to match an existing user by email.
	var user *models.User
	if account.Email != "" {
		user, _ = s.repos.User.GetByEmail(ctx, tenantID, account.Email)
	}

	if user == nil {
		// Create a brand-new user for this social identity.
		randBytes := make([]byte, 8)
		_, _ = rand.Read(randBytes)
		username := account.Provider + "_" + hex.EncodeToString(randBytes)
		email := account.Email
		if email == "" {
			email = username + "@social.local"
		}
		pwBytes := make([]byte, 16)
		_, _ = rand.Read(pwBytes)
		user = &models.User{
			ID:            uuid.New(),
			TenantID:      tenantID,
			Username:      username,
			Email:         email,
			PasswordHash:  hex.EncodeToString(pwBytes),
			Status:        models.UserStatusActive,
			EmailVerified: account.Email != "",
			FirstName:     account.Name,
			Avatar:        account.Avatar,
		}
		if err := s.repos.User.Create(ctx, user); err != nil {
			return nil, fmt.Errorf("create social user: %w", err)
		}
	}

	// Link the social account to the resolved user.
	linked := *account
	linked.ID = uuid.New()
	linked.TenantID = tenantID
	linked.UserID = user.ID
	if err := s.repos.SocialAccount.Create(ctx, &linked); err != nil {
		s.logger.WithError(err).Warn("failed to link social account after user resolution")
	}
	return user, nil
}
