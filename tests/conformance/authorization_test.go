//go:build conformance

package conformance

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"shieldgate/tests/conformance/fixture"
)

// RFC 6749 §4.1.2.1 and §10.15: before the client and redirect URI are
// validated, errors are shown to the user, never redirected (open redirector)
func TestAuthorize_InvalidClientOrRedirectURI_NotRedirected(t *testing.T) {
	tests := []struct {
		name  string
		extra map[string]string
	}{
		{"unknown client", map[string]string{"client_id": "no-such-client"}},
		{"missing client", map[string]string{"client_id": ""}},
		{"unregistered redirect_uri", map[string]string{"redirect_uri": "https://attacker.example/cb"}},
		{"redirect_uri with extra path", map[string]string{"redirect_uri": fixture.RedirectURI + "/x"}},
		{"redirect_uri with extra query", map[string]string{"redirect_uri": fixture.RedirectURI + "?a=b"}},
		{"missing redirect_uri", map[string]string{"redirect_uri": ""}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			b := newBrowser(t)

			// Act
			resp := b.get("/oauth/authorize", authRequest(fixture.ConfidentialClient, tt.extra))

			// Assert
			assert.Equal(t, http.StatusBadRequest, resp.status)
			assert.Empty(t, resp.header.Get("Location"))
		})
	}
}

// RFC 6749 §4.1.2.1, OIDC Core §3.1.2.6, RFC 9207 §2: once the redirect URI
// is trusted, errors are returned to it with state and iss
func TestAuthorize_InvalidRequest_ErrorRedirectedWithStateAndIss(t *testing.T) {
	tests := []struct {
		name      string
		clientID  string
		extra     map[string]string
		wantError string
	}{
		{"unsupported response_type", fixture.ConfidentialClient, map[string]string{"response_type": "token"}, "unsupported_response_type"},
		{"implicit id_token", fixture.ConfidentialClient, map[string]string{"response_type": "id_token"}, "unsupported_response_type"},
		{"scope not allowed", fixture.ConfidentialClient, map[string]string{"scope": "openid admin"}, "invalid_scope"},
		{"public client without PKCE", fixture.PublicClient, nil, "invalid_request"},
		{"public client with plain PKCE", fixture.PublicClient, map[string]string{"code_challenge": strings.Repeat("a", 43), "code_challenge_method": "plain"}, "invalid_request"},
		{"prompt=none combined", fixture.ConfidentialClient, map[string]string{"prompt": "none login"}, "invalid_request"},
		{"negative max_age", fixture.ConfidentialClient, map[string]string{"max_age": "-1"}, "invalid_request"},
		{"prompt=none without session", fixture.ConfidentialClient, map[string]string{"prompt": "none"}, "login_required"},
		// OIDC Core §6.1/§6.2: unsupported request objects are rejected, not ignored
		{"request object", fixture.ConfidentialClient, map[string]string{"request": "eyJhbGciOiJub25lIn0.e30."}, "request_not_supported"},
		{"request_uri", fixture.ConfidentialClient, map[string]string{"request_uri": "https://rp.conformance.test/req.jwt"}, "request_uri_not_supported"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			b := newBrowser(t)
			q := authRequest(tt.clientID, tt.extra)

			// Act
			loc := b.get("/oauth/authorize", q).location(t)

			// Assert
			assert.Equal(t, fixture.RedirectURI, loc.Scheme+"://"+loc.Host+loc.Path)
			assert.Equal(t, tt.wantError, loc.Query().Get("error"))
			assert.Equal(t, q.Get("state"), loc.Query().Get("state"))
			assert.Equal(t, b.base, loc.Query().Get("iss"))
			assert.Empty(t, loc.Query().Get("code"))
		})
	}
}

// OIDC Core §3.1.2.1: the authorization endpoint MUST support POST with
// form-serialized parameters
func TestAuthorize_FormPost_CompletesCodeFlow(t *testing.T) {
	// Arrange
	b := newBrowser(t)
	q := authRequest(fixture.ConfidentialClient, nil)

	// Act
	page := b.post("/oauth/authorize", q)
	loc := b.login(page, fixture.UserEmail).location(t)

	// Assert
	assert.Equal(t, q.Get("state"), loc.Query().Get("state"))
	tokens := b.exchange(fixture.ConfidentialClient, loc.Query().Get("code"), "")
	b.verifyIDToken(tokens["id_token"].(string), fixture.ConfidentialClient, q.Get("nonce"))
}

// OIDC Core §3.1.2.6: the user denying consent yields access_denied
func TestAuthorize_ConsentDenied_AccessDenied(t *testing.T) {
	// Arrange: user 2 has not consented to the post client yet
	b := newBrowser(t)
	q := authRequest(fixture.ConfidentialClientPost, map[string]string{"scope": "openid phone"})
	page := b.get("/oauth/authorize", q)
	form := formFields(page.body)
	form.Set("username", fixture.User2Email)
	form.Set("password", fixture.UserPassword)
	consentPage := b.post("/oauth/login", form)

	// Act
	loc := b.consent(consentPage, "deny").location(t)

	// Assert
	assert.Equal(t, "access_denied", loc.Query().Get("error"))
	assert.Equal(t, q.Get("state"), loc.Query().Get("state"))
}

// OIDC Core §3.1.2.1 (prompt, max_age) and §3.1.2.3 (re-authentication)
func TestAuthorize_SessionAndPrompt(t *testing.T) {
	// Arrange: a signed-in user who has consented
	b := newBrowser(t)
	b.code(authRequest(fixture.ConfidentialClient, nil))

	t.Run("SSO: a second request needs no login", func(t *testing.T) {
		// Act
		resp := b.get("/oauth/authorize", authRequest(fixture.ConfidentialClient, nil))

		// Assert
		assert.NotEmpty(t, resp.location(t).Query().Get("code"))
	})
	t.Run("prompt=none with session returns a code", func(t *testing.T) {
		// Act
		loc := b.get("/oauth/authorize", authRequest(fixture.ConfidentialClient, map[string]string{"prompt": "none"})).location(t)

		// Assert
		assert.NotEmpty(t, loc.Query().Get("code"))
		assert.Empty(t, loc.Query().Get("error"))
	})
	t.Run("prompt=login forces the login page", func(t *testing.T) {
		// Act
		resp := b.get("/oauth/authorize", authRequest(fixture.ConfidentialClient, map[string]string{"prompt": "login"}))

		// Assert
		assert.True(t, isLoginPage(resp))
	})
	t.Run("max_age=0 with prompt=none requires login", func(t *testing.T) {
		// Act
		loc := b.get("/oauth/authorize", authRequest(fixture.ConfidentialClient, map[string]string{"prompt": "none", "max_age": "0"})).location(t)

		// Assert
		assert.Equal(t, "login_required", loc.Query().Get("error"))
	})
	t.Run("prompt=consent with prompt=none requires consent", func(t *testing.T) {
		// Arrange: scopes never granted to this client
		q := authRequest(fixture.ConfidentialClient, map[string]string{"prompt": "none", "scope": "openid phone write"})

		// Act
		loc := b.get("/oauth/authorize", q).location(t)

		// Assert
		assert.Equal(t, "consent_required", loc.Query().Get("error"))
	})
}

// OIDC Core §3.1.2.1: max_age makes auth_time REQUIRED in the ID token
func TestAuthorize_MaxAge_IDTokenHasAuthTime(t *testing.T) {
	// Arrange
	b := newBrowser(t)
	q := authRequest(fixture.ConfidentialClient, map[string]string{"max_age": "300"})

	// Act
	tokens := b.exchange(fixture.ConfidentialClient, b.code(q), "")

	// Assert
	claims := b.verifyIDToken(tokens["id_token"].(string), fixture.ConfidentialClient, q.Get("nonce"))
	require.Contains(t, claims, "auth_time")
	assert.Greater(t, claims["auth_time"].(float64), float64(0))
}

// Login CSRF: the login form must carry the CSRF token bound to the browser
func TestLogin_WithoutCSRFToken_Rejected(t *testing.T) {
	// Arrange
	b := newBrowser(t)
	page := b.get("/oauth/authorize", authRequest(fixture.ConfidentialClient, nil))
	form := formFields(page.body)
	form.Del("csrf_token")
	form.Set("username", fixture.UserEmail)
	form.Set("password", fixture.UserPassword)

	// Act
	resp := b.post("/oauth/login", form)

	// Assert
	assert.Equal(t, http.StatusBadRequest, resp.status)
	assert.Empty(t, resp.header.Get("Location"))
}
