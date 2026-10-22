package tests

// session_fakes_test.go provides in-memory session and consent repositories
// so handler tests run the real SessionService without a database.

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"shieldgate/internal/models"
	"shieldgate/internal/services"
)

type memSessionRepo struct {
	mu       sync.Mutex
	sessions map[string]*models.Session
}

func (r *memSessionRepo) Create(ctx context.Context, s *models.Session) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	stored := *s
	r.sessions[s.TokenHash] = &stored
	return nil
}

func (r *memSessionRepo) GetByTokenHash(ctx context.Context, tenantID uuid.UUID, hash string) (*models.Session, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.sessions[hash]; ok && s.TenantID == tenantID {
		copied := *s
		return &copied, nil
	}
	return nil, models.ErrSessionNotFound
}

func (r *memSessionRepo) DeleteByTokenHash(ctx context.Context, tenantID uuid.UUID, hash string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.sessions, hash)
	return nil
}

func (r *memSessionRepo) DeleteByUserID(ctx context.Context, tenantID, userID uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, s := range r.sessions {
		if s.TenantID == tenantID && s.UserID == userID {
			delete(r.sessions, k)
		}
	}
	return nil
}

func (r *memSessionRepo) DeleteExpired(ctx context.Context) error { return nil }

// count returns the number of stored sessions
func (r *memSessionRepo) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sessions)
}

// ageAll shifts every session's auth_time into the past
func (r *memSessionRepo) ageAll(d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.sessions {
		s.AuthTime = s.AuthTime.Add(-d)
	}
}

type memConsentRepo struct {
	mu       sync.Mutex
	consents map[string]*models.Consent
}

func consentKey(tenantID, userID, clientID uuid.UUID) string {
	return tenantID.String() + userID.String() + clientID.String()
}

func (r *memConsentRepo) Get(ctx context.Context, tenantID, userID, clientID uuid.UUID) (*models.Consent, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.consents[consentKey(tenantID, userID, clientID)]; ok {
		copied := *c
		return &copied, nil
	}
	return nil, models.ErrResourceNotFound
}

func (r *memConsentRepo) Upsert(ctx context.Context, c *models.Consent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	stored := *c
	r.consents[consentKey(c.TenantID, c.UserID, c.ClientID)] = &stored
	return nil
}

func (r *memConsentRepo) Delete(ctx context.Context, tenantID, userID, clientID uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.consents, consentKey(tenantID, userID, clientID))
	return nil
}

// sessionStore bundles a real SessionService with its in-memory storage
type sessionStore struct {
	services.SessionService
	sessions *memSessionRepo
	consents *memConsentRepo
}

func newSessionStore() *sessionStore {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	sessions := &memSessionRepo{sessions: map[string]*models.Session{}}
	consents := &memConsentRepo{consents: map[string]*models.Consent{}}
	return &sessionStore{
		SessionService: services.NewSessionService(sessions, consents, 8*time.Hour, logger),
		sessions:       sessions,
		consents:       consents,
	}
}

// preConsented returns a store in which any user has already granted any
// client every scope, for tests that are not about consent
func preConsented() services.SessionService {
	return alwaysConsented{newSessionStore()}
}

type alwaysConsented struct{ *sessionStore }

func (alwaysConsented) HasConsent(ctx context.Context, tenantID, userID, clientID uuid.UUID, scope string) (bool, error) {
	return true, nil
}
