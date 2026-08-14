package tests

// session_consent_test.go covers Phase 3 service logic: server-side SSO
// sessions and remembered consent grants.

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"shieldgate/internal/models"
)

func TestSession_CreateGetRevoke(t *testing.T) {
	svc, repos := newAuthServiceWithFakes()
	ctx := context.Background()
	tenantID, userID := uuid.New(), uuid.New()

	token, session, err := svc.CreateSession(ctx, tenantID, userID, "203.0.113.9", "TestAgent/1.0")
	require.NoError(t, err)
	assert.NotEmpty(t, token)
	assert.Equal(t, userID, session.UserID)
	assert.False(t, session.AuthTime.IsZero())

	// Raw token must not be stored (only its hash)
	_, err = repos.Session.GetByToken(ctx, tenantID, token)
	assert.Error(t, err, "raw session token must not be stored")

	// Round trip through the service
	got, err := svc.GetSession(ctx, tenantID, token)
	require.NoError(t, err)
	assert.Equal(t, session.ID, got.ID)

	// Revoked sessions no longer resolve
	require.NoError(t, svc.RevokeSession(ctx, tenantID, token))
	_, err = svc.GetSession(ctx, tenantID, token)
	assert.ErrorIs(t, err, models.ErrSessionNotFound)
}

func TestSession_ExpiredRejected(t *testing.T) {
	svc, repos := newAuthServiceWithFakes()
	ctx := context.Background()
	tenantID := uuid.New()

	token, session, err := svc.CreateSession(ctx, tenantID, uuid.New(), "", "")
	require.NoError(t, err)

	// Force expiry in the store
	stored, err := repos.Session.GetByToken(ctx, tenantID, session.Token)
	require.NoError(t, err)
	stored.ExpiresAt = time.Now().Add(-time.Minute)
	require.NoError(t, repos.Session.Create(ctx, stored)) // overwrite in fake

	_, err = svc.GetSession(ctx, tenantID, token)
	assert.ErrorIs(t, err, models.ErrSessionExpired)
}

func TestSession_WrongTenantRejected(t *testing.T) {
	svc, _ := newAuthServiceWithFakes()
	ctx := context.Background()

	token, _, err := svc.CreateSession(ctx, uuid.New(), uuid.New(), "", "")
	require.NoError(t, err)

	_, err = svc.GetSession(ctx, uuid.New(), token)
	assert.ErrorIs(t, err, models.ErrSessionNotFound)
}

func TestConsent_GrantAndUnion(t *testing.T) {
	svc, _ := newAuthServiceWithFakes()
	ctx := context.Background()
	tenantID, userID, clientID := uuid.New(), uuid.New(), uuid.New()

	// Nothing granted yet
	has, err := svc.HasConsent(ctx, tenantID, userID, clientID, "read")
	require.NoError(t, err)
	assert.False(t, has)

	// Grant "read" — covers "read" but not "read write"
	require.NoError(t, svc.GrantConsent(ctx, tenantID, userID, clientID, "read"))
	has, err = svc.HasConsent(ctx, tenantID, userID, clientID, "read")
	require.NoError(t, err)
	assert.True(t, has)
	has, err = svc.HasConsent(ctx, tenantID, userID, clientID, "read write")
	require.NoError(t, err)
	assert.False(t, has)

	// Grants accumulate: after also granting "write", the union covers both
	require.NoError(t, svc.GrantConsent(ctx, tenantID, userID, clientID, "write"))
	has, err = svc.HasConsent(ctx, tenantID, userID, clientID, "read write")
	require.NoError(t, err)
	assert.True(t, has)

	// A different client shares nothing
	has, err = svc.HasConsent(ctx, tenantID, userID, uuid.New(), "read")
	require.NoError(t, err)
	assert.False(t, has)
}
