//go:build conformance

package conformance

import (
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"shieldgate/tests/conformance/fixture"
)

// OIDC Core §5.3 and §5.4; RFC 6750 §2.1 and §3
func TestUserInfo_ClaimsFollowGrantedScopes(t *testing.T) {
	// Arrange
	b := newBrowser(t)
	q := authRequest(fixture.ConfidentialClient, map[string]string{"scope": "openid email"})
	tokens := b.exchange(fixture.ConfidentialClient, b.code(q), "")
	idClaims := b.verifyIDToken(tokens["id_token"].(string), fixture.ConfidentialClient, q.Get("nonce"))

	// Act
	resp := b.userinfo(tokens["access_token"].(string))

	// Assert
	require.Equal(t, http.StatusOK, resp.status, resp.body)
	claims := resp.json(t)
	assert.Equal(t, idClaims["sub"], claims["sub"], "§5.3.2: sub MUST match the ID token")
	assert.Equal(t, fixture.UserEmail, claims["email"])
	assert.Equal(t, true, claims["email_verified"])
	assert.NotContains(t, claims, "name", "profile was not granted")
	assert.NotContains(t, claims, "phone_number", "phone was not granted")
}

// RFC 6750 §3.1
func TestUserInfo_BadToken_BearerChallenge(t *testing.T) {
	// Arrange
	b := newBrowser(t)

	// Act
	missing := b.userinfo("")
	invalid := b.userinfo("not-a-token")

	// Assert
	assert.Equal(t, http.StatusUnauthorized, missing.status)
	assert.True(t, strings.HasPrefix(missing.header.Get("WWW-Authenticate"), "Bearer"))
	assert.Equal(t, http.StatusUnauthorized, invalid.status)
	assert.Contains(t, invalid.header.Get("WWW-Authenticate"), `error="invalid_token"`)
}

// RFC 6749 §6 and OIDC Core §12.2: refresh rotates the refresh token, keeps
// the subject and auth_time, and omits the nonce
func TestRefresh_RotatesAndKeepsIdentity(t *testing.T) {
	// Arrange
	b := newBrowser(t)
	q := authRequest(fixture.ConfidentialClient, map[string]string{"scope": "openid profile read"})
	first := b.exchange(fixture.ConfidentialClient, b.code(q), "")
	firstClaims := b.verifyIDToken(first["id_token"].(string), fixture.ConfidentialClient, q.Get("nonce"))

	// Act
	resp := b.tokenRequest(fixture.ConfidentialClient, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {first["refresh_token"].(string)}, "scope": {"openid read"}})

	// Assert
	require.Equal(t, http.StatusOK, resp.status, resp.body)
	second := resp.json(t)
	assert.NotEqual(t, first["refresh_token"], second["refresh_token"], "the refresh token is rotated")
	assert.Equal(t, "openid read", second["scope"], "§6: the scope may be narrowed")
	claims := b.verifyIDToken(second["id_token"].(string), fixture.ConfidentialClient, "")
	assert.Equal(t, firstClaims["sub"], claims["sub"], "§12.2: same sub")
	assert.Equal(t, firstClaims["auth_time"], claims["auth_time"], "§12.2: auth_time is the original authentication")
	assert.NotContains(t, claims, "nonce", "§12.2: no nonce on refresh")

	widened := b.tokenRequest(fixture.ConfidentialClient, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {second["refresh_token"].(string)}, "scope": {"openid read write"}})
	assert.Equal(t, "invalid_scope", errorCode(t, widened), "§6: the scope may not be widened")
}

// RFC 9700 §4.14.2 (OAuth 2.0 Security BCP): replaying a rotated refresh
// token revokes the whole grant, including tokens already rotated in
func TestRefresh_Replay_RevokesFamily(t *testing.T) {
	// Arrange
	b := newBrowser(t)
	first := b.exchange(fixture.ConfidentialClient, b.code(authRequest(fixture.ConfidentialClient, nil)), "")
	refresh := func(token string) response {
		return b.tokenRequest(fixture.ConfidentialClient, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {token}})
	}
	rotated := refresh(first["refresh_token"].(string))
	require.Equal(t, http.StatusOK, rotated.status)
	current := rotated.json(t)

	// Act
	replay := refresh(first["refresh_token"].(string))

	// Assert
	assert.Equal(t, "invalid_grant", errorCode(t, replay))
	assert.Equal(t, "invalid_grant", errorCode(t, refresh(current["refresh_token"].(string))), "the current token is revoked too")
	assert.Equal(t, http.StatusUnauthorized, b.userinfo(current["access_token"].(string)).status, "and so are its access tokens")
}

// RFC 9700 §4.14.2: concurrent use of one refresh token must not fork the
// grant into several live token chains
func TestRefresh_ConcurrentReplay_NoForkedChains(t *testing.T) {
	// Arrange
	b := newBrowser(t)
	token := b.exchange(fixture.ConfidentialClient, b.code(authRequest(fixture.ConfidentialClient, nil)), "")["refresh_token"].(string)
	const attempts = 10
	var mu sync.Mutex
	var issued []string
	var wg sync.WaitGroup
	start := make(chan struct{})

	// Act
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			resp := b.tokenRequest(fixture.ConfidentialClient, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {token}})
			if resp.status == http.StatusOK {
				mu.Lock()
				issued = append(issued, resp.json(t)["refresh_token"].(string))
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()

	// Assert
	assert.LessOrEqual(t, len(issued), 1, "at most one request may rotate the token")
	for _, rt := range issued {
		resp := b.tokenRequest(fixture.ConfidentialClient, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}})
		assert.Equal(t, "invalid_grant", errorCode(t, resp), "the replays revoked the grant")
	}
}

// RFC 7009 §2: revocation
func TestRevocation(t *testing.T) {
	t.Run("revoking a refresh token revokes the grant", func(t *testing.T) {
		// Arrange
		b := newBrowser(t)
		tokens := b.exchange(fixture.ConfidentialClient, b.code(authRequest(fixture.ConfidentialClient, nil)), "")

		// Act
		resp := b.postWithClient("/oauth/revoke", fixture.ConfidentialClient, url.Values{"token": {tokens["refresh_token"].(string)}, "token_type_hint": {"refresh_token"}})

		// Assert
		assert.Equal(t, http.StatusOK, resp.status)
		assert.Equal(t, http.StatusUnauthorized, b.userinfo(tokens["access_token"].(string)).status, "§2.1: SHOULD also invalidate access tokens of the grant")
	})
	t.Run("revoking an access token", func(t *testing.T) {
		// Arrange
		b := newBrowser(t)
		tokens := b.exchange(fixture.ConfidentialClient, b.code(authRequest(fixture.ConfidentialClient, nil)), "")

		// Act
		resp := b.postWithClient("/oauth/revoke", fixture.ConfidentialClient, url.Values{"token": {tokens["access_token"].(string)}})

		// Assert
		assert.Equal(t, http.StatusOK, resp.status)
		assert.Equal(t, http.StatusUnauthorized, b.userinfo(tokens["access_token"].(string)).status)
	})
	t.Run("unknown token", func(t *testing.T) {
		// Act
		resp := newBrowser(t).postWithClient("/oauth/revoke", fixture.ConfidentialClient, url.Values{"token": {"unknown"}})

		// Assert
		assert.Equal(t, http.StatusOK, resp.status, "§2.2: invalid tokens do not cause an error")
	})
	t.Run("another client's token is left alone", func(t *testing.T) {
		// Arrange
		b := newBrowser(t)
		tokens := b.exchange(fixture.ConfidentialClient, b.code(authRequest(fixture.ConfidentialClient, nil)), "")

		// Act
		b.postWithClient("/oauth/revoke", fixture.MachineClient, url.Values{"token": {tokens["access_token"].(string)}})

		// Assert
		assert.Equal(t, http.StatusOK, b.userinfo(tokens["access_token"].(string)).status, "§2.1: only the client the token was issued to may revoke it")
	})
	t.Run("client authentication required", func(t *testing.T) {
		// Act
		resp := newBrowser(t).post("/oauth/revoke", url.Values{"token": {"x"}})

		// Assert
		assert.Equal(t, http.StatusUnauthorized, resp.status)
	})
}

// RFC 7662 §2
func TestIntrospection(t *testing.T) {
	// Arrange
	b := newBrowser(t)
	cc := b.tokenRequest(fixture.MachineClient, url.Values{"grant_type": {"client_credentials"}, "scope": {"read"}}).json(t)
	token := cc["access_token"].(string)

	// Act
	active := b.postWithClient("/oauth/introspect", fixture.MachineClient, url.Values{"token": {token}})
	unknown := b.postWithClient("/oauth/introspect", fixture.MachineClient, url.Values{"token": {"unknown"}})
	anonymous := b.post("/oauth/introspect", url.Values{"token": {token}})
	public := b.post("/oauth/introspect", url.Values{"token": {token}, "client_id": {fixture.PublicClient}})

	// Assert
	require.Equal(t, http.StatusOK, active.status, active.body)
	claims := active.json(t)
	assert.Equal(t, true, claims["active"])
	assert.Equal(t, "read", claims["scope"])
	assert.Equal(t, fixture.MachineClient, claims["client_id"])
	assert.Greater(t, claims["exp"].(float64), float64(0))
	assert.Equal(t, map[string]interface{}{"active": false}, unknown.json(t), "§2.2: inactive tokens reveal nothing else")
	assert.Equal(t, http.StatusUnauthorized, anonymous.status, "§2.1: the caller must authenticate")
	assert.Equal(t, http.StatusUnauthorized, public.status, "a public client cannot authenticate")
}
