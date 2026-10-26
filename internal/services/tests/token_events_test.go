package tests

// token_events_test.go covers roadmap 4.5: the auth service reports every
// token issuance, revocation and replay to its TokenEventSink.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"shieldgate/internal/jwtkeys"
	"shieldgate/internal/models"
	"shieldgate/internal/repo"
	"shieldgate/internal/services"
	"shieldgate/tests/utils"
)

type recordingSink struct {
	mu     sync.Mutex
	events []models.TokenEvent
}

func (s *recordingSink) TokenEvent(ctx context.Context, ev models.TokenEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, ev)
}

// last returns the most recent event
func (s *recordingSink) last(t *testing.T) models.TokenEvent {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	require.NotEmpty(t, s.events)
	return s.events[len(s.events)-1]
}

func (s *recordingSink) ofType(typ string) []models.TokenEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []models.TokenEvent
	for _, ev := range s.events {
		if ev.Type == typ {
			out = append(out, ev)
		}
	}
	return out
}

func newAuthServiceWithSink() (services.AuthService, *repo.Repositories, *recordingSink) {
	repos := newFakeRepositories()
	cfg := utils.CreateTestConfig()
	sink := &recordingSink{}
	svc := services.NewAuthService(repos, cfg, jwtkeys.NewHMAC(cfg.JWTSecret), quietLogger(), services.WithTokenEvents(sink))
	return svc, repos, sink
}

func TestTokenEvents_IssuedForEveryGrant(t *testing.T) {
	ctx := context.Background()
	tenantID, clientID, userID := uuid.New(), uuid.New(), uuid.New()

	t.Run("authorization code and refresh", func(t *testing.T) {
		// Arrange
		svc, repos, sink := newAuthServiceWithSink()
		registerClient(t, repos, tenantID, clientID)
		code, err := svc.GenerateAuthorizationCode(ctx, tenantID, clientID, userID, "https://app/cb", "read", "", "", "", time.Now(), nil)
		require.NoError(t, err)

		// Act
		tokens, err := svc.ExchangeAuthorizationCode(ctx, tenantID, code.Code, clientID.String(), "", "https://app/cb", "")
		require.NoError(t, err)
		exchanged := sink.last(t)
		_, err = svc.RefreshTokens(ctx, tenantID, tokens.RefreshToken, clientID.String(), "")
		require.NoError(t, err)
		refreshed := sink.last(t)

		// Assert
		assert.Equal(t, models.TokenEvent{Type: models.TokenEventIssued, TenantID: tenantID, ClientID: clientID, UserID: &userID,
			GrantType: models.GrantTypeAuthorizationCode, Scope: "read", FamilyID: code.ID}, exchanged)
		assert.Equal(t, models.GrantTypeRefreshToken, refreshed.GrantType)
		assert.Equal(t, code.ID, refreshed.FamilyID, "rotation stays in the family")
	})

	t.Run("client credentials", func(t *testing.T) {
		// Arrange
		svc, _, sink := newAuthServiceWithSink()
		client := &models.Client{ID: clientID, TenantID: tenantID, ClientID: "svc"}

		// Act
		_, err := svc.GenerateClientCredentialsTokens(ctx, tenantID, client, "read")

		// Assert
		require.NoError(t, err)
		ev := sink.last(t)
		assert.Equal(t, models.GrantTypeClientCredentials, ev.GrantType)
		assert.Nil(t, ev.UserID, "a client token has no user")
	})

	t.Run("device code", func(t *testing.T) {
		// Arrange
		svc, repos, sink := newAuthServiceWithSink()
		client := deviceClient(tenantID)
		require.NoError(t, repos.Client.Create(ctx, client))
		user := seedUser(t, repos, tenantID)
		auth, err := svc.CreateDeviceAuthorization(ctx, tenantID, client, "read")
		require.NoError(t, err)
		require.NoError(t, svc.ApproveDeviceCode(ctx, tenantID, auth.UserCode, user.ID, []string{"pwd"}))

		// Act
		_, err = svc.ExchangeDeviceCode(ctx, tenantID, client, auth.DeviceCode)

		// Assert
		require.NoError(t, err)
		assert.Equal(t, models.GrantTypeDeviceCode, sink.last(t).GrantType)
		assert.Equal(t, &user.ID, sink.last(t).UserID)
	})

	t.Run("token exchange", func(t *testing.T) {
		// Arrange
		svc, repos, sink := newAuthServiceWithSink()
		registerClient(t, repos, tenantID, clientID)
		subject, err := svc.GenerateTokens(ctx, tenantID, clientID, userID, "read", false)
		require.NoError(t, err)
		actor := &models.Client{ID: uuid.New(), TenantID: tenantID, ClientID: "backend",
			GrantTypes: models.StringArray{models.GrantTypeTokenExchange}, Scopes: models.StringArray{"read"}}

		// Act
		_, err = svc.ExchangeToken(ctx, tenantID, actor, subject.AccessToken, models.TokenTypeAccessToken, "read")

		// Assert
		require.NoError(t, err)
		ev := sink.last(t)
		assert.Equal(t, models.GrantTypeTokenExchange, ev.GrantType)
		assert.Equal(t, "backend", ev.Actor)
		assert.Equal(t, &userID, ev.UserID, "the exchanged token keeps the subject")
	})
}

func TestTokenEvents_ReuseDetected(t *testing.T) {
	ctx := context.Background()
	tenantID, clientID, userID := uuid.New(), uuid.New(), uuid.New()

	t.Run("authorization code replay", func(t *testing.T) {
		// Arrange
		svc, repos, sink := newAuthServiceWithSink()
		registerClient(t, repos, tenantID, clientID)
		code, err := svc.GenerateAuthorizationCode(ctx, tenantID, clientID, userID, "https://app/cb", "read", "", "", "", time.Now(), nil)
		require.NoError(t, err)
		_, err = svc.ExchangeAuthorizationCode(ctx, tenantID, code.Code, clientID.String(), "", "https://app/cb", "")
		require.NoError(t, err)

		// Act
		_, err = svc.ExchangeAuthorizationCode(ctx, tenantID, code.Code, clientID.String(), "", "https://app/cb", "")

		// Assert
		assert.ErrorIs(t, err, models.ErrInvalidGrant)
		reuse := sink.ofType(models.TokenEventReuseDetected)
		require.Len(t, reuse, 1)
		assert.Equal(t, models.CredentialAuthorizationCode, reuse[0].Credential)
		assert.Equal(t, code.ID, reuse[0].FamilyID)
		assert.Equal(t, &userID, reuse[0].UserID)
	})

	t.Run("refresh token replay", func(t *testing.T) {
		// Arrange
		svc, repos, sink := newAuthServiceWithSink()
		registerClient(t, repos, tenantID, clientID)
		original, err := svc.GenerateTokens(ctx, tenantID, clientID, userID, "read", false)
		require.NoError(t, err)
		_, err = svc.RefreshTokens(ctx, tenantID, original.RefreshToken, clientID.String(), "")
		require.NoError(t, err)

		// Act
		_, err = svc.RefreshTokens(ctx, tenantID, original.RefreshToken, clientID.String(), "")

		// Assert
		assert.ErrorIs(t, err, models.ErrInvalidGrant)
		reuse := sink.ofType(models.TokenEventReuseDetected)
		require.Len(t, reuse, 1)
		assert.Equal(t, models.CredentialRefreshToken, reuse[0].Credential)
	})
}

func TestTokenEvents_Revoked(t *testing.T) {
	ctx := context.Background()
	tenantID, clientID, userID := uuid.New(), uuid.New(), uuid.New()
	tests := []struct {
		name  string
		token func(*models.TokenResponse) string
	}{
		{"refresh token", func(r *models.TokenResponse) string { return r.RefreshToken }},
		{"access token", func(r *models.TokenResponse) string { return r.AccessToken }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			svc, repos, sink := newAuthServiceWithSink()
			registerClient(t, repos, tenantID, clientID)
			tokens, err := svc.GenerateTokens(ctx, tenantID, clientID, userID, "read", false)
			require.NoError(t, err)

			// Act
			err = svc.RevokeToken(ctx, tenantID, tt.token(tokens), "", clientID)
			otherClientErr := svc.RevokeToken(ctx, tenantID, tt.token(tokens), "", uuid.New())

			// Assert
			require.NoError(t, err)
			require.NoError(t, otherClientErr)
			revoked := sink.ofType(models.TokenEventRevoked)
			require.Len(t, revoked, 1, "only a real revocation is reported")
			assert.Equal(t, clientID, revoked[0].ClientID)
			assert.Equal(t, &userID, revoked[0].UserID)
		})
	}
}

func TestTokenEvents_FailedGrant_NoEvent(t *testing.T) {
	// Arrange
	svc, _, sink := newAuthServiceWithSink()

	// Act
	_, err := svc.ExchangeAuthorizationCode(context.Background(), uuid.New(), "no-such-code", uuid.NewString(), "", "https://app/cb", "")

	// Assert
	assert.ErrorIs(t, err, models.ErrInvalidGrant)
	assert.Empty(t, sink.events, "failed requests are counted by the HTTP layer, not audited")
}
