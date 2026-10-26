//go:build conformance

package conformance

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"shieldgate/tests/conformance/fixture"
)

// OpenID Connect RP-Initiated Logout 1.0 §2 and §3
func TestLogout_WithIDTokenHint_EndsSessionAndRedirects(t *testing.T) {
	// Arrange
	b := newBrowser(t)
	tokens := b.exchange(fixture.ConfidentialClient, b.code(authRequest(fixture.ConfidentialClient, nil)), "")

	// Act
	loc := b.get("/oauth/logout", url.Values{
		"id_token_hint":            {tokens["id_token"].(string)},
		"post_logout_redirect_uri": {fixture.PostLogoutURI},
		"state":                    {"logout-state"},
	}).location(t)
	after := b.get("/oauth/authorize", authRequest(fixture.ConfidentialClient, map[string]string{"prompt": "none"})).location(t)

	// Assert
	assert.Equal(t, fixture.PostLogoutURI, loc.Scheme+"://"+loc.Host+loc.Path)
	assert.Equal(t, "logout-state", loc.Query().Get("state"), "§3: state is passed back")
	assert.Equal(t, "login_required", after.Query().Get("error"), "the session has ended")
}

// RP-Initiated Logout §3: only registered post_logout_redirect_uri values
func TestLogout_UnregisteredRedirect_NotRedirected(t *testing.T) {
	// Arrange
	b := newBrowser(t)
	tokens := b.exchange(fixture.ConfidentialClient, b.code(authRequest(fixture.ConfidentialClient, nil)), "")

	// Act
	resp := b.get("/oauth/logout", url.Values{
		"id_token_hint":            {tokens["id_token"].(string)},
		"post_logout_redirect_uri": {"https://attacker.example/"},
	})

	// Assert
	assert.Equal(t, http.StatusBadRequest, resp.status)
	assert.Empty(t, resp.header.Get("Location"))
}

// RP-Initiated Logout §2 and §6: without an id_token_hint the user confirms,
// so a third-party page cannot sign the user out
func TestLogout_WithoutHint_AsksForConfirmation(t *testing.T) {
	// Arrange
	b := newBrowser(t)
	b.code(authRequest(fixture.ConfidentialClient, nil))

	// Act
	resp := b.get("/oauth/logout", nil)
	stillSignedIn := b.get("/oauth/authorize", authRequest(fixture.ConfidentialClient, map[string]string{"prompt": "none"})).location(t)

	// Assert
	require.Equal(t, http.StatusOK, resp.status)
	assert.Contains(t, resp.body, `action="/oauth/logout"`, "a confirmation form is shown")
	assert.NotEmpty(t, stillSignedIn.Query().Get("code"), "the session is still alive")
}
