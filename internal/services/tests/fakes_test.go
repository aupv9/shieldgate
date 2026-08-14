package tests

// fakes_test.go provides in-memory repository implementations so service-level
// OAuth flows (code exchange, rotation, revocation) can be tested without a database.

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"

	"shieldgate/internal/models"
	"shieldgate/internal/repo"
)

// --- fakeClientRepo ---

type fakeClientRepo struct {
	mu      sync.Mutex
	clients map[uuid.UUID]*models.Client
}

func newFakeClientRepo() *fakeClientRepo {
	return &fakeClientRepo{clients: make(map[uuid.UUID]*models.Client)}
}

func (r *fakeClientRepo) Create(ctx context.Context, client *models.Client) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	stored := *client
	r.clients[client.ID] = &stored
	return nil
}

func (r *fakeClientRepo) GetByID(ctx context.Context, tenantID, clientID uuid.UUID) (*models.Client, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.clients[clientID]; ok && c.TenantID == tenantID {
		copied := *c
		return &copied, nil
	}
	return nil, models.ErrClientNotFound
}

func (r *fakeClientRepo) GetByClientID(ctx context.Context, tenantID uuid.UUID, clientID string) (*models.Client, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.clients {
		if c.TenantID == tenantID && c.ClientID == clientID {
			copied := *c
			return &copied, nil
		}
	}
	return nil, models.ErrClientNotFound
}

func (r *fakeClientRepo) Update(ctx context.Context, client *models.Client) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	stored := *client
	r.clients[client.ID] = &stored
	return nil
}

func (r *fakeClientRepo) Delete(ctx context.Context, tenantID, clientID uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.clients, clientID)
	return nil
}

func (r *fakeClientRepo) List(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]*models.Client, int64, error) {
	return nil, 0, nil
}

// --- fakeAuthCodeRepo ---

type fakeAuthCodeRepo struct {
	mu    sync.Mutex
	codes map[string]*models.AuthorizationCode
}

func newFakeAuthCodeRepo() *fakeAuthCodeRepo {
	return &fakeAuthCodeRepo{codes: make(map[string]*models.AuthorizationCode)}
}

func (r *fakeAuthCodeRepo) Create(ctx context.Context, code *models.AuthorizationCode) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	stored := *code
	r.codes[code.Code] = &stored
	return nil
}

func (r *fakeAuthCodeRepo) GetByCode(ctx context.Context, tenantID uuid.UUID, code string) (*models.AuthorizationCode, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.codes[code]; ok && c.TenantID == tenantID {
		copied := *c
		return &copied, nil
	}
	return nil, models.ErrAuthCodeNotFound
}

func (r *fakeAuthCodeRepo) Consume(ctx context.Context, tenantID uuid.UUID, code string) (*models.AuthorizationCode, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.codes[code]
	if !ok || c.TenantID != tenantID {
		return nil, models.ErrAuthCodeNotFound
	}
	if c.UsedAt != nil {
		copied := *c
		return &copied, models.ErrAuthCodeAlreadyUsed
	}
	now := time.Now()
	c.UsedAt = &now
	copied := *c
	return &copied, nil
}

func (r *fakeAuthCodeRepo) Delete(ctx context.Context, tenantID uuid.UUID, code string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.codes, code)
	return nil
}

func (r *fakeAuthCodeRepo) DeleteExpired(ctx context.Context) error { return nil }

// --- fakeAccessTokenRepo ---

type fakeAccessTokenRepo struct {
	mu     sync.Mutex
	tokens map[string]*models.AccessToken
}

func newFakeAccessTokenRepo() *fakeAccessTokenRepo {
	return &fakeAccessTokenRepo{tokens: make(map[string]*models.AccessToken)}
}

func (r *fakeAccessTokenRepo) Create(ctx context.Context, token *models.AccessToken) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	stored := *token
	r.tokens[token.Token] = &stored
	return nil
}

func (r *fakeAccessTokenRepo) GetByToken(ctx context.Context, tenantID uuid.UUID, token string) (*models.AccessToken, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if t, ok := r.tokens[token]; ok && t.TenantID == tenantID {
		copied := *t
		return &copied, nil
	}
	return nil, models.ErrAccessTokenNotFound
}

func (r *fakeAccessTokenRepo) Delete(ctx context.Context, tenantID uuid.UUID, token string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.tokens, token)
	return nil
}

func (r *fakeAccessTokenRepo) DeleteExpired(ctx context.Context) error { return nil }

func (r *fakeAccessTokenRepo) DeleteByUserID(ctx context.Context, tenantID, userID uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, t := range r.tokens {
		if t.TenantID == tenantID && t.UserID == userID {
			delete(r.tokens, k)
		}
	}
	return nil
}

func (r *fakeAccessTokenRepo) DeleteByFamilyID(ctx context.Context, tenantID, familyID uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, t := range r.tokens {
		if t.TenantID == tenantID && t.FamilyID == familyID {
			delete(r.tokens, k)
		}
	}
	return nil
}

// --- fakeRefreshTokenRepo ---

type fakeRefreshTokenRepo struct {
	mu     sync.Mutex
	tokens map[string]*models.RefreshToken
}

func newFakeRefreshTokenRepo() *fakeRefreshTokenRepo {
	return &fakeRefreshTokenRepo{tokens: make(map[string]*models.RefreshToken)}
}

func (r *fakeRefreshTokenRepo) Create(ctx context.Context, token *models.RefreshToken) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	stored := *token
	r.tokens[token.Token] = &stored
	return nil
}

func (r *fakeRefreshTokenRepo) GetByToken(ctx context.Context, tenantID uuid.UUID, token string) (*models.RefreshToken, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if t, ok := r.tokens[token]; ok && t.TenantID == tenantID {
		copied := *t
		return &copied, nil
	}
	return nil, models.ErrRefreshTokenNotFound
}

func (r *fakeRefreshTokenRepo) Revoke(ctx context.Context, tenantID uuid.UUID, token string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if t, ok := r.tokens[token]; ok && t.TenantID == tenantID && t.RevokedAt == nil {
		now := time.Now()
		t.RevokedAt = &now
	}
	return nil
}

func (r *fakeRefreshTokenRepo) Delete(ctx context.Context, tenantID uuid.UUID, token string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.tokens, token)
	return nil
}

func (r *fakeRefreshTokenRepo) DeleteExpired(ctx context.Context) error { return nil }

func (r *fakeRefreshTokenRepo) DeleteByUserID(ctx context.Context, tenantID, userID uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, t := range r.tokens {
		if t.TenantID == tenantID && t.UserID == userID {
			delete(r.tokens, k)
		}
	}
	return nil
}

func (r *fakeRefreshTokenRepo) DeleteByFamilyID(ctx context.Context, tenantID, familyID uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, t := range r.tokens {
		if t.TenantID == tenantID && t.FamilyID == familyID {
			delete(r.tokens, k)
		}
	}
	return nil
}

// --- fakeUserRepo ---

type fakeUserRepo struct {
	mu    sync.Mutex
	users map[uuid.UUID]*models.User
}

func newFakeUserRepo() *fakeUserRepo {
	return &fakeUserRepo{users: make(map[uuid.UUID]*models.User)}
}

func (r *fakeUserRepo) Create(ctx context.Context, user *models.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	stored := *user
	r.users[user.ID] = &stored
	return nil
}

func (r *fakeUserRepo) GetByID(ctx context.Context, tenantID, userID uuid.UUID) (*models.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if u, ok := r.users[userID]; ok && u.TenantID == tenantID {
		copied := *u
		return &copied, nil
	}
	return nil, models.ErrUserNotFound
}

func (r *fakeUserRepo) GetByEmail(ctx context.Context, tenantID uuid.UUID, email string) (*models.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, u := range r.users {
		if u.TenantID == tenantID && u.Email == email {
			copied := *u
			return &copied, nil
		}
	}
	return nil, models.ErrUserNotFound
}

func (r *fakeUserRepo) GetByUsername(ctx context.Context, tenantID uuid.UUID, username string) (*models.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, u := range r.users {
		if u.TenantID == tenantID && u.Username == username {
			copied := *u
			return &copied, nil
		}
	}
	return nil, models.ErrUserNotFound
}

func (r *fakeUserRepo) Update(ctx context.Context, user *models.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	stored := *user
	r.users[user.ID] = &stored
	return nil
}

func (r *fakeUserRepo) Delete(ctx context.Context, tenantID, userID uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.users, userID)
	return nil
}

func (r *fakeUserRepo) List(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]*models.User, int64, error) {
	return nil, 0, nil
}

// --- fakeDeviceCodeRepo ---

type fakeDeviceCodeRepo struct {
	mu    sync.Mutex
	codes map[string]*models.DeviceCode
}

func newFakeDeviceCodeRepo() *fakeDeviceCodeRepo {
	return &fakeDeviceCodeRepo{codes: make(map[string]*models.DeviceCode)}
}

func (r *fakeDeviceCodeRepo) Create(ctx context.Context, code *models.DeviceCode) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	stored := *code
	r.codes[code.DeviceCode] = &stored
	return nil
}

func (r *fakeDeviceCodeRepo) GetByDeviceCode(ctx context.Context, tenantID uuid.UUID, deviceCode string) (*models.DeviceCode, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.codes[deviceCode]; ok && c.TenantID == tenantID {
		copied := *c
		return &copied, nil
	}
	return nil, models.ErrDeviceCodeNotFound
}

func (r *fakeDeviceCodeRepo) GetByUserCode(ctx context.Context, tenantID uuid.UUID, userCode string) (*models.DeviceCode, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.codes {
		if c.TenantID == tenantID && c.UserCode == userCode {
			copied := *c
			return &copied, nil
		}
	}
	return nil, models.ErrDeviceCodeNotFound
}

func (r *fakeDeviceCodeRepo) Update(ctx context.Context, code *models.DeviceCode) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	stored := *code
	r.codes[code.DeviceCode] = &stored
	return nil
}

func (r *fakeDeviceCodeRepo) Delete(ctx context.Context, tenantID uuid.UUID, deviceCode string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.codes, deviceCode)
	return nil
}

func (r *fakeDeviceCodeRepo) DeleteExpired(ctx context.Context) error { return nil }

// newFakeRepositories wires the fakes into a repo.Repositories aggregate
func newFakeRepositories() *repo.Repositories {
	return &repo.Repositories{
		Client:       newFakeClientRepo(),
		AuthCode:     newFakeAuthCodeRepo(),
		AccessToken:  newFakeAccessTokenRepo(),
		RefreshToken: newFakeRefreshTokenRepo(),
		DeviceCode:   newFakeDeviceCodeRepo(),
		User:         newFakeUserRepo(),
	}
}
