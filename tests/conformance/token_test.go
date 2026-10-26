//go:build conformance

package conformance

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"shieldgate/tests/conformance/fixture"
)

// OIDC Core §3.1.3.3 and §3.1.3.7; RFC 6749 §5.1
func TestCodeFlow_ConfidentialClient_TokenResponseAndIDToken(t *testing.T) {
	for _, clientID := range []string{fixture.ConfidentialClient, fixture.ConfidentialClientPost} {
		t.Run(clientID, func(t *testing.T) {
			// Arrange
			b := newBrowser(t)
			q := authRequest(clientID, nil)
			code := b.code(q)

			// Act
			resp := b.tokenRequest(clientID, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {fixture.RedirectURI}})

			// Assert
			require.Equal(t, http.StatusOK, resp.status, resp.body)
			assert.Contains(t, resp.header.Get("Cache-Control"), "no-store", "RFC 6749 §5.1")
			assert.Equal(t, "no-cache", resp.header.Get("Pragma"), "RFC 6749 §5.1")
			tokens := resp.json(t)
			assert.True(t, strings.EqualFold(tokens["token_type"].(string), "Bearer"))
			assert.NotEmpty(t, tokens["access_token"])
			assert.Greater(t, tokens["expires_in"].(float64), float64(0))
			claims := b.verifyIDToken(tokens["id_token"].(string), clientID, q.Get("nonce"))
			assert.Equal(t, fixture.UserID.String(), claims["sub"])
			assert.Equal(t, leftHalfHash(tokens["access_token"].(string)), claims["at_hash"], "§3.1.3.6: at_hash")
			authTime, _ := claims["auth_time"].(float64)
			assert.InDelta(t, float64(time.Now().Unix()), authTime, 300, "auth_time is when the user logged in")
		})
	}
}

// RFC 7636 §4.5 and §4.6: a public client proves possession of the verifier
func TestCodeFlow_PublicClientPKCE(t *testing.T) {
	tests := []struct {
		name       string
		verifier   func(verifier string) string
		wantStatus int
	}{
		{"correct verifier", func(v string) string { return v }, http.StatusOK},
		{"missing verifier", func(string) string { return "" }, http.StatusBadRequest},
		{"wrong verifier", func(v string) string { return v + "x" }, http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			b := newBrowser(t)
			verifier, challenge := pkce()
			q := authRequest(fixture.PublicClient, map[string]string{"code_challenge": challenge, "code_challenge_method": "S256"})
			form := url.Values{"grant_type": {"authorization_code"}, "code": {b.code(q)}, "redirect_uri": {fixture.RedirectURI}}
			if v := tt.verifier(verifier); v != "" {
				form.Set("code_verifier", v)
			}

			// Act
			resp := b.tokenRequest(fixture.PublicClient, form)

			// Assert
			require.Equal(t, tt.wantStatus, resp.status, resp.body)
			if tt.wantStatus == http.StatusOK {
				b.verifyIDToken(resp.json(t)["id_token"].(string), fixture.PublicClient, q.Get("nonce"))
			} else {
				assert.Equal(t, "invalid_grant", errorCode(t, resp))
			}
		})
	}
}

// RFC 6749 §4.1.2 and §10.5: a code is single use, and replaying it revokes
// the tokens issued for it
func TestCodeFlow_CodeReplay_RejectedAndTokensRevoked(t *testing.T) {
	// Arrange
	b := newBrowser(t)
	code := b.code(authRequest(fixture.ConfidentialClient, nil))
	first := b.exchange(fixture.ConfidentialClient, code, "")

	// Act
	replay := b.tokenRequest(fixture.ConfidentialClient, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {fixture.RedirectURI}})

	// Assert
	assert.Equal(t, "invalid_grant", errorCode(t, replay))
	assert.Equal(t, http.StatusUnauthorized, b.userinfo(first["access_token"].(string)).status, "SHOULD revoke the tokens issued for the code")
	refresh := b.tokenRequest(fixture.ConfidentialClient, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {first["refresh_token"].(string)}})
	assert.Equal(t, "invalid_grant", errorCode(t, refresh))
}

// RFC 6749 §4.1.3: the code is bound to the client and the redirect URI
func TestCodeFlow_CodeBoundToClientAndRedirectURI(t *testing.T) {
	t.Run("another client", func(t *testing.T) {
		// Arrange
		b := newBrowser(t)
		code := b.code(authRequest(fixture.ConfidentialClient, nil))

		// Act
		resp := b.tokenRequest(fixture.ConfidentialClientPost, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {fixture.RedirectURI}})

		// Assert
		assert.Equal(t, "invalid_grant", errorCode(t, resp))
	})
	t.Run("another redirect_uri", func(t *testing.T) {
		// Arrange
		b := newBrowser(t)
		code := b.code(authRequest(fixture.ConfidentialClient, nil))

		// Act
		resp := b.tokenRequest(fixture.ConfidentialClient, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {fixture.OIDFRedirectURIs[0]}})

		// Assert
		assert.Equal(t, "invalid_grant", errorCode(t, resp))
	})
}

// RFC 6749 §5.2: token endpoint error responses
func TestTokenEndpoint_ErrorResponses(t *testing.T) {
	b := newBrowser(t)
	t.Run("wrong secret with HTTP Basic", func(t *testing.T) {
		// Arrange
		req := url.Values{"grant_type": {"client_credentials"}}

		// Act
		resp := b.postBasic("/oauth/token", fixture.MachineClient, "wrong-secret", req)

		// Assert
		assert.Equal(t, http.StatusUnauthorized, resp.status, "§5.2: 401 when the client used the Authorization header")
		assert.Equal(t, "invalid_client", errorCode(t, resp))
		assert.True(t, strings.HasPrefix(resp.header.Get("WWW-Authenticate"), "Basic"), "§5.2: MUST include WWW-Authenticate")
	})
	t.Run("unknown grant type", func(t *testing.T) {
		// Act
		resp := b.tokenRequest(fixture.ConfidentialClient, url.Values{"grant_type": {"urn:example:unknown"}})

		// Assert
		assert.Equal(t, http.StatusBadRequest, resp.status)
		assert.Equal(t, "unsupported_grant_type", errorCode(t, resp))
	})
	t.Run("grant type not registered for the client", func(t *testing.T) {
		// Act
		resp := b.tokenRequest(fixture.MachineClient, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"x"}})

		// Assert
		assert.Equal(t, "unauthorized_client", errorCode(t, resp))
	})
	t.Run("unknown code", func(t *testing.T) {
		// Act
		resp := b.tokenRequest(fixture.ConfidentialClient, url.Values{"grant_type": {"authorization_code"}, "code": {"nope"}, "redirect_uri": {fixture.RedirectURI}})

		// Assert
		assert.Equal(t, http.StatusBadRequest, resp.status)
		assert.Equal(t, "invalid_grant", errorCode(t, resp))
	})
	t.Run("scope beyond the registration", func(t *testing.T) {
		// Act
		resp := b.tokenRequest(fixture.MachineClient, url.Values{"grant_type": {"client_credentials"}, "scope": {"read admin"}})

		// Assert
		assert.Equal(t, "invalid_scope", errorCode(t, resp))
	})
}

// RFC 6749 §4.4: client credentials, no refresh token (§4.4.3)
func TestClientCredentials_AccessTokenWithoutRefreshToken(t *testing.T) {
	// Arrange
	b := newBrowser(t)

	// Act
	resp := b.tokenRequest(fixture.MachineClient, url.Values{"grant_type": {"client_credentials"}, "scope": {"read"}})

	// Assert
	require.Equal(t, http.StatusOK, resp.status, resp.body)
	tokens := resp.json(t)
	assert.NotEmpty(t, tokens["access_token"])
	assert.NotContains(t, tokens, "refresh_token", "§4.4.3: a refresh token SHOULD NOT be included")
	assert.NotContains(t, tokens, "id_token")
	assert.Equal(t, "read", tokens["scope"])
}

func (b *browser) postBasic(path, user, password string, form url.Values) response {
	b.t.Helper()
	req, err := http.NewRequest(http.MethodPost, b.base+path, strings.NewReader(form.Encode()))
	require.NoError(b.t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(user, password)
	return b.do(req)
}

func withValue(v url.Values, key, value string) url.Values {
	out := url.Values{}
	for k, vs := range v {
		out[k] = vs
	}
	out.Set(key, value)
	return out
}

// errorCode returns the OAuth error code of an error response
func errorCode(t *testing.T, r response) string {
	t.Helper()
	require.GreaterOrEqual(t, r.status, 400, "expected an error response: %s", r.body)
	code, _ := r.json(t)["error"].(string)
	return code
}
