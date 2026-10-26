//go:build conformance

package conformance

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// OIDC Discovery 1.0 §3 and §4.3; RFC 8414 §2 and §3.3
func TestDiscovery_ProviderMetadata(t *testing.T) {
	// Arrange
	b := newBrowser(t)

	// Act
	resp := b.get("/.well-known/openid-configuration", nil)
	oauthResp := b.get("/.well-known/oauth-authorization-server", nil)

	// Assert
	require.Equal(t, http.StatusOK, resp.status)
	assert.True(t, strings.HasPrefix(resp.header.Get("Content-Type"), "application/json"))
	meta := resp.json(t)
	assert.Equal(t, b.base, meta["issuer"], "§4.3: issuer is identical to the URL discovery was fetched from")
	for _, field := range []string{"authorization_endpoint", "token_endpoint", "jwks_uri", "userinfo_endpoint"} {
		value, _ := meta[field].(string)
		assert.True(t, strings.HasPrefix(value, b.base+"/"), "%s is served by the issuer: %q", field, value)
	}
	assert.Contains(t, meta["response_types_supported"], "code", "REQUIRED: response_types_supported")
	assert.Contains(t, meta["subject_types_supported"], "public", "REQUIRED: subject_types_supported")
	assert.Contains(t, meta["id_token_signing_alg_values_supported"], "RS256", "RS256 MUST be supported (§3)")
	assert.Contains(t, meta["scopes_supported"], "openid", "scopes_supported includes openid (§3)")
	assert.Contains(t, meta["code_challenge_methods_supported"], "S256", "RFC 8414 §2")
	assert.NotContains(t, meta["code_challenge_methods_supported"], "plain", "plain PKCE is not offered")
	assert.Equal(t, true, meta["authorization_response_iss_parameter_supported"], "RFC 9207 §3")
	// request_uri_parameter_supported defaults to true when absent (§3)
	assert.Equal(t, false, meta["request_uri_parameter_supported"])

	require.Equal(t, http.StatusOK, oauthResp.status)
	assert.Equal(t, b.base, oauthResp.json(t)["issuer"], "RFC 8414 §3.3: same issuer")
}

// RFC 7517 §4 and §5; OIDC Core §10.1
func TestJWKS_PublishesOnlyPublicSigningKeys(t *testing.T) {
	// Arrange
	b := newBrowser(t)

	// Act
	resp := b.get("/.well-known/jwks.json", nil)

	// Assert
	require.Equal(t, http.StatusOK, resp.status)
	keys, _ := resp.json(t)["keys"].([]interface{})
	require.NotEmpty(t, keys)
	kids := map[string]bool{}
	for _, raw := range keys {
		key := raw.(map[string]interface{})
		assert.Equal(t, "RSA", key["kty"])
		kid, _ := key["kid"].(string)
		assert.NotEmpty(t, kid, "§10.1: kid is required when the set has several keys, and lets RPs rotate")
		assert.False(t, kids[kid], "kid values are unique")
		kids[kid] = true
		if use, ok := key["use"]; ok {
			assert.Equal(t, "sig", use)
		}
		for _, private := range []string{"d", "p", "q", "dp", "dq", "qi"} {
			assert.NotContains(t, key, private, "private key member %q must never be published", private)
		}
	}
}
