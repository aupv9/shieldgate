package services

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"shieldgate/internal/models"
	"shieldgate/internal/repo"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

const (
	// defaultInitialAccessTokenTTL and maxInitialAccessTokenTTL bound how
	// long an initial access token can register clients
	defaultInitialAccessTokenTTL = 24 * time.Hour
	maxInitialAccessTokenTTL     = 30 * 24 * time.Hour
	maxInitialAccessTokenUses    = 1000
	// registrationTokenBytes is the entropy of initial and registration
	// access tokens (256 bits)
	registrationTokenBytes = 32
)

type registrationServiceImpl struct {
	repos   *repo.Repositories
	clients ClientService
	baseURL string
	logger  *logrus.Logger
}

// NewRegistrationService creates the dynamic client registration service
// (RFC 7591, RFC 7592). baseURL is the public server URL used in
// registration_client_uri.
func NewRegistrationService(repos *repo.Repositories, clients ClientService, baseURL string, logger *logrus.Logger) RegistrationService {
	return &registrationServiceImpl{repos: repos, clients: clients, baseURL: strings.TrimSuffix(baseURL, "/"), logger: logger}
}

func (s *registrationServiceImpl) CreateInitialAccessToken(ctx context.Context, tenantID uuid.UUID, createdBy *uuid.UUID, req *models.CreateInitialAccessTokenRequest) (*models.CreatedInitialAccessToken, error) {
	scopes := dedupe(req.Scopes)
	if len(scopes) == 0 {
		return nil, invalidMetadata("scopes must not be empty")
	}
	for _, scope := range scopes {
		if !validScopeToken(scope) {
			return nil, invalidMetadata("invalid scope " + scope)
		}
	}
	ttl := time.Duration(req.ExpiresIn) * time.Second
	if req.ExpiresIn == 0 {
		ttl = defaultInitialAccessTokenTTL
	}
	if ttl <= 0 || ttl > maxInitialAccessTokenTTL {
		return nil, invalidMetadata("expires_in must be between 1 second and 30 days")
	}
	maxUses := req.MaxUses
	if maxUses == 0 {
		maxUses = 1
	}
	if maxUses < 0 || maxUses > maxInitialAccessTokenUses {
		return nil, invalidMetadata("max_uses must be between 1 and 1000")
	}

	token, err := randomToken(registrationTokenBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate initial access token: %w", err)
	}
	record := &models.InitialAccessToken{
		ID:          uuid.New(),
		TenantID:    tenantID,
		TokenHash:   hashToken(token),
		Description: req.Description,
		Scopes:      models.StringArray(scopes),
		MaxUses:     maxUses,
		CreatedBy:   createdBy,
		ExpiresAt:   time.Now().Add(ttl),
		CreatedAt:   time.Now(),
	}
	if err := s.repos.InitialAccess.Create(ctx, record); err != nil {
		return nil, err
	}
	return &models.CreatedInitialAccessToken{InitialAccessToken: record, Token: token}, nil
}

func (s *registrationServiceImpl) ListInitialAccessTokens(ctx context.Context, tenantID uuid.UUID) ([]*models.InitialAccessToken, error) {
	return s.repos.InitialAccess.List(ctx, tenantID)
}

func (s *registrationServiceImpl) RevokeInitialAccessToken(ctx context.Context, tenantID, id uuid.UUID) error {
	return s.repos.InitialAccess.Revoke(ctx, tenantID, id)
}

// Register creates a client from its metadata (RFC 7591 §3). The metadata
// is validated before the initial access token is used, so a malformed
// request does not spend one of the token's uses.
func (s *registrationServiceImpl) Register(ctx context.Context, tenantID uuid.UUID, initialAccessToken string, meta *models.ClientMetadata) (*models.ClientRegistrationResponse, error) {
	if initialAccessToken == "" {
		return nil, models.ErrInvalidToken
	}
	iatHash := hashToken(initialAccessToken)
	iat, err := s.repos.InitialAccess.GetByHash(ctx, tenantID, iatHash)
	if errors.Is(err, models.ErrInitialAccessTokenNotFound) {
		return nil, models.ErrInvalidToken
	}
	if err != nil {
		return nil, err
	}

	md, err := validateClientMetadata(meta)
	if err != nil {
		return nil, err
	}
	if len(md.scopes) == 0 {
		md.scopes = append([]string(nil), iat.Scopes...)
	}
	if !ScopeIsSubset(strings.Join(md.scopes, " "), strings.Join(iat.Scopes, " ")) {
		return nil, invalidMetadata("scope exceeds what this initial access token allows")
	}

	if _, err := s.repos.InitialAccess.Consume(ctx, tenantID, iatHash); err != nil {
		if errors.Is(err, models.ErrInitialAccessTokenNotFound) {
			// Expired, revoked or used up since it was read
			return nil, models.ErrInvalidToken
		}
		return nil, err
	}

	registrationToken, err := randomToken(registrationTokenBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate registration access token: %w", err)
	}
	var plainSecret, secretHash string
	if !md.isPublic() {
		if plainSecret, err = generateClientSecret(); err != nil {
			return nil, fmt.Errorf("failed to generate client secret: %w", err)
		}
		if secretHash, err = hashClientSecret(plainSecret); err != nil {
			return nil, fmt.Errorf("failed to hash client secret: %w", err)
		}
	}
	client := &models.Client{
		ID:                      uuid.New(),
		TenantID:                tenantID,
		ClientID:                generateClientID(),
		ClientSecret:            secretHash,
		Name:                    md.name,
		RedirectURIs:            append(models.StringArray{}, md.redirectURIs...),
		PostLogoutRedirectURIs:  append(models.StringArray{}, md.postLogoutRedirectURIs...),
		GrantTypes:              models.StringArray(md.grantTypes),
		Scopes:                  models.StringArray(md.scopes),
		IsPublic:                md.isPublic(),
		TokenEndpointAuthMethod: md.authMethod,
		DynamicallyRegistered:   true,
		RegistrationAccessToken: hashToken(registrationToken),
		CreatedAt:               time.Now(),
	}
	if err := s.repos.Client.Create(ctx, client); err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"tenant_id":            tenantID,
		"client_id":            client.ClientID,
		"initial_access_token": iat.ID,
		"auth_method":          client.TokenEndpointAuthMethod,
	}).Info("client registered dynamically")

	resp := s.response(client)
	resp.ClientSecret = plainSecret
	if plainSecret != "" {
		// The secret does not expire (RFC 7591 §3.2.1)
		never := int64(0)
		resp.ClientSecretExpiresAt = &never
	}
	resp.RegistrationAccessToken = registrationToken
	return resp, nil
}

func (s *registrationServiceImpl) Read(ctx context.Context, tenantID uuid.UUID, clientID, registrationToken string) (*models.ClientRegistrationResponse, error) {
	client, err := s.authorize(ctx, tenantID, clientID, registrationToken)
	if err != nil {
		return nil, err
	}
	return s.response(client), nil
}

// Update replaces the client's metadata (RFC 7592 §2.2). The client type
// (public or confidential) cannot change, and scope can only narrow: the
// initial access token that capped it is no longer at hand.
func (s *registrationServiceImpl) Update(ctx context.Context, tenantID uuid.UUID, clientID, registrationToken string, meta *models.ClientMetadata) (*models.ClientRegistrationResponse, error) {
	client, err := s.authorize(ctx, tenantID, clientID, registrationToken)
	if err != nil {
		return nil, err
	}
	if meta.ClientID != clientID {
		return nil, invalidMetadata("client_id must match the client being updated")
	}
	md, err := validateClientMetadata(meta)
	if err != nil {
		return nil, err
	}
	if md.isPublic() != client.IsPublic {
		return nil, invalidMetadata("token_endpoint_auth_method cannot switch between public and confidential")
	}
	if len(md.scopes) == 0 {
		md.scopes = append([]string(nil), client.Scopes...)
	}
	if !ScopeIsSubset(strings.Join(md.scopes, " "), strings.Join(client.Scopes, " ")) {
		return nil, invalidMetadata("scope can only be narrowed")
	}

	client.Name = md.name
	client.RedirectURIs = append(models.StringArray{}, md.redirectURIs...)
	client.PostLogoutRedirectURIs = append(models.StringArray{}, md.postLogoutRedirectURIs...)
	client.GrantTypes = models.StringArray(md.grantTypes)
	client.Scopes = models.StringArray(md.scopes)
	client.TokenEndpointAuthMethod = md.authMethod
	client.UpdatedAt = time.Now()
	if err := s.repos.Client.Update(ctx, client); err != nil {
		return nil, fmt.Errorf("failed to update client: %w", err)
	}
	return s.response(client), nil
}

// Delete removes the client and revokes its tokens (RFC 7592 §2.3)
func (s *registrationServiceImpl) Delete(ctx context.Context, tenantID uuid.UUID, clientID, registrationToken string) error {
	client, err := s.authorize(ctx, tenantID, clientID, registrationToken)
	if err != nil {
		return err
	}
	return s.clients.Delete(ctx, tenantID, client.ID)
}

// authorize checks a registration access token. Every failure looks the
// same, so the endpoint does not reveal which client IDs exist.
func (s *registrationServiceImpl) authorize(ctx context.Context, tenantID uuid.UUID, clientID, registrationToken string) (*models.Client, error) {
	if registrationToken == "" {
		return nil, models.ErrInvalidToken
	}
	client, err := s.repos.Client.GetByClientID(ctx, tenantID, clientID)
	if err != nil {
		if errors.Is(err, models.ErrClientNotFound) {
			return nil, models.ErrInvalidToken
		}
		return nil, err
	}
	if !client.DynamicallyRegistered || client.RegistrationAccessToken == "" ||
		subtle.ConstantTimeCompare([]byte(client.RegistrationAccessToken), []byte(hashToken(registrationToken))) != 1 {
		return nil, models.ErrInvalidToken
	}
	return client, nil
}

// response returns the client information response for a client
func (s *registrationServiceImpl) response(client *models.Client) *models.ClientRegistrationResponse {
	var responseTypes []string
	if client.HasGrantType(models.GrantTypeAuthorizationCode) {
		responseTypes = []string{responseTypeCode}
	}
	return &models.ClientRegistrationResponse{
		ClientMetadata: models.ClientMetadata{
			RedirectURIs:            client.RedirectURIs,
			PostLogoutRedirectURIs:  client.PostLogoutRedirectURIs,
			TokenEndpointAuthMethod: client.TokenEndpointAuthMethod,
			GrantTypes:              client.GrantTypes,
			ResponseTypes:           responseTypes,
			ClientName:              client.Name,
			Scope:                   strings.Join(client.Scopes, " "),
		},
		ClientID:              client.ClientID,
		ClientIDIssuedAt:      client.CreatedAt.Unix(),
		RegistrationClientURI: s.baseURL + "/oauth/register/" + url.PathEscape(client.ClientID),
	}
}
