//go:build conformance

// Package conformance checks a running ShieldGate server, black-box over
// HTTP, against the requirements of OAuth 2.0 (RFC 6749, 6750, 7009, 7636,
// 7662, 9207), OpenID Connect Core 1.0, Discovery 1.0 and RP-Initiated
// Logout. Each test names the section it checks.
//
// Start a seeded server, then run the tests:
//
//	DATABASE_URL=postgres://... scripts/conformance/serve.sh
//	SHIELDGATE_CONFORMANCE_URL=http://127.0.0.1:18100 go test -tags conformance ./tests/conformance/
//
// scripts/conformance/run.sh does both against a throwaway database.
package conformance

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"shieldgate/tests/conformance/fixture"
)

// baseURL is the server under test, which is also its issuer
func baseURL(t *testing.T) string {
	t.Helper()
	u := os.Getenv("SHIELDGATE_CONFORMANCE_URL")
	if u == "" {
		t.Skip("SHIELDGATE_CONFORMANCE_URL not set")
	}
	return strings.TrimSuffix(u, "/")
}

// browser is a user agent with its own cookies that does not follow
// redirects, so each authorization response can be inspected
type browser struct {
	t      *testing.T
	base   string
	client *http.Client
}

func newBrowser(t *testing.T) *browser {
	t.Helper()
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	return &browser{t: t, base: baseURL(t), client: &http.Client{
		Jar:     jar,
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}
}

// response is a read HTTP response
type response struct {
	status int
	header http.Header
	body   string
}

func (r response) json(t *testing.T) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(r.body), &m), "body: %s", r.body)
	return m
}

// location parses the Location header of a redirect
func (r response) location(t *testing.T) *url.URL {
	t.Helper()
	require.Contains(t, []int{http.StatusFound, http.StatusSeeOther}, r.status, "expected a redirect, got %d: %.300s", r.status, r.body)
	u, err := url.Parse(r.header.Get("Location"))
	require.NoError(t, err)
	return u
}

func (b *browser) do(req *http.Request) response {
	b.t.Helper()
	resp, err := b.client.Do(req)
	require.NoError(b.t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(b.t, err)
	return response{status: resp.StatusCode, header: resp.Header, body: string(body)}
}

func (b *browser) get(path string, query url.Values) response {
	b.t.Helper()
	u := b.base + path
	if query != nil {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequest(http.MethodGet, u, nil)
	require.NoError(b.t, err)
	return b.do(req)
}

func (b *browser) post(path string, form url.Values) response {
	b.t.Helper()
	req, err := http.NewRequest(http.MethodPost, b.base+path, strings.NewReader(form.Encode()))
	require.NoError(b.t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return b.do(req)
}

var hiddenInput = regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)"`)

// formFields returns the hidden fields of the HTML form in body
func formFields(body string) url.Values {
	v := url.Values{}
	for _, m := range hiddenInput.FindAllStringSubmatch(body, -1) {
		v.Set(m[1], html.UnescapeString(m[2]))
	}
	return v
}

func isLoginPage(r response) bool {
	return r.status == http.StatusOK && strings.Contains(r.body, `action="/oauth/login"`)
}

func isConsentPage(r response) bool {
	return r.status == http.StatusOK && strings.Contains(r.body, `action="/oauth/consent"`)
}

// login submits the login form in page and, when asked, approves consent;
// it returns the final response (the redirect to the client)
func (b *browser) login(page response, email string) response {
	b.t.Helper()
	require.True(b.t, isLoginPage(page), "expected the login page, got %d: %.300s", page.status, page.body)
	form := formFields(page.body)
	form.Set("username", email)
	form.Set("password", fixture.UserPassword)
	resp := b.post("/oauth/login", form)
	if isConsentPage(resp) {
		resp = b.consent(resp, "allow")
	}
	return resp
}

func (b *browser) consent(page response, decision string) response {
	b.t.Helper()
	require.True(b.t, isConsentPage(page), "expected the consent page, got %d: %.300s", page.status, page.body)
	form := formFields(page.body)
	form.Set("decision", decision)
	return b.post("/oauth/consent", form)
}

// authRequest builds authorization request parameters for clientID with a
// fresh state and nonce; extra overrides or adds parameters ("" removes)
func authRequest(clientID string, extra map[string]string) url.Values {
	q := url.Values{
		"response_type": {"code"},
		"client_id":     {clientID},
		"redirect_uri":  {fixture.RedirectURI},
		"scope":         {"openid profile email"},
		"state":         {randomString()},
		"nonce":         {randomString()},
	}
	for k, v := range extra {
		if v == "" {
			q.Del(k)
		} else {
			q.Set(k, v)
		}
	}
	return q
}

func randomString() string {
	return uuid.NewString()
}

// pkce returns a verifier and its S256 challenge (RFC 7636 §4.2)
func pkce() (verifier, challenge string) {
	verifier = base64.RawURLEncoding.EncodeToString([]byte(randomString() + "-0123456789-abcdefghij-klmnop"))
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

// authorize runs the authorization request to its redirect back to the
// client, logging in as the first seeded user when asked
func (b *browser) authorize(q url.Values) *url.URL {
	b.t.Helper()
	resp := b.get("/oauth/authorize", q)
	if isLoginPage(resp) {
		resp = b.login(resp, fixture.UserEmail)
	} else if isConsentPage(resp) {
		resp = b.consent(resp, "allow")
	}
	return resp.location(b.t)
}

// code runs the authorization request and returns the code, checking the
// response parameters of RFC 6749 §4.1.2 and RFC 9207
func (b *browser) code(q url.Values) string {
	b.t.Helper()
	loc := b.authorize(q)
	require.Equal(b.t, fixture.RedirectURI, loc.Scheme+"://"+loc.Host+loc.Path, "redirected to the registered URI")
	params := loc.Query()
	require.Empty(b.t, params.Get("error"), "authorization failed: %s", loc)
	require.Equal(b.t, q.Get("state"), params.Get("state"), "state is returned unchanged (RFC 6749 §4.1.2)")
	require.Equal(b.t, b.base, params.Get("iss"), "iss identifies the issuer (RFC 9207 §2)")
	require.NotEmpty(b.t, params.Get("code"))
	return params.Get("code")
}

// tokenRequest posts to the token endpoint authenticating as clientID with
// client_secret_basic (confidential), client_secret_post (the post client)
// or no secret (public)
func (b *browser) tokenRequest(clientID string, form url.Values) response {
	b.t.Helper()
	req, err := http.NewRequest(http.MethodPost, b.base+"/oauth/token", strings.NewReader(clientForm(clientID, form).Encode()))
	require.NoError(b.t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if clientID == fixture.ConfidentialClient || clientID == fixture.MachineClient {
		req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(fixture.ClientSecret))
	}
	return b.do(req)
}

func clientForm(clientID string, form url.Values) url.Values {
	out := url.Values{}
	for k, v := range form {
		out[k] = v
	}
	switch clientID {
	case fixture.ConfidentialClientPost:
		out.Set("client_id", clientID)
		out.Set("client_secret", fixture.ClientSecret)
	case fixture.PublicClient:
		out.Set("client_id", clientID)
	}
	return out
}

// exchange redeems code and requires success
func (b *browser) exchange(clientID, code, verifier string) map[string]interface{} {
	b.t.Helper()
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {fixture.RedirectURI}}
	if verifier != "" {
		form.Set("code_verifier", verifier)
	}
	resp := b.tokenRequest(clientID, form)
	require.Equal(b.t, http.StatusOK, resp.status, "token response: %s", resp.body)
	return resp.json(b.t)
}

// postWithClient posts form to path authenticated as a confidential client
func (b *browser) postWithClient(path, clientID string, form url.Values) response {
	b.t.Helper()
	req, err := http.NewRequest(http.MethodPost, b.base+path, strings.NewReader(form.Encode()))
	require.NoError(b.t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(fixture.ClientSecret))
	return b.do(req)
}

func (b *browser) userinfo(accessToken string) response {
	b.t.Helper()
	req, err := http.NewRequest(http.MethodGet, b.base+"/userinfo", nil)
	require.NoError(b.t, err)
	if accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}
	return b.do(req)
}

// verifyIDToken checks an ID token as OIDC Core §3.1.3.7 tells a relying
// party to, and returns its claims
func (b *browser) verifyIDToken(raw, clientID, nonce string) jwt.MapClaims {
	b.t.Helper()
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(raw, claims, b.jwksKeyfunc(),
		jwt.WithValidMethods([]string{"RS256"}), // §3.1.3.7 step 7: the advertised alg
		jwt.WithIssuer(b.base),                  // step 2: iss equals the issuer exactly
		jwt.WithAudience(clientID),              // step 3: aud contains the client_id
		jwt.WithExpirationRequired(),            // step 9: exp is in the future
		jwt.WithIssuedAt(),                      // step 10: iat is not in the future
		jwt.WithLeeway(5*time.Second),
	)
	require.NoError(b.t, err, "ID token must verify")
	require.NotEqual(b.t, "at+jwt", token.Header["typ"], "an ID token is not typed as an access token")

	// Step 4/5: a single audience, or azp naming the client
	if aud, ok := claims["aud"].([]interface{}); ok && len(aud) > 1 {
		require.Equal(b.t, clientID, claims["azp"])
	}
	require.NotEmpty(b.t, claims["sub"])
	require.LessOrEqual(b.t, len(claims["sub"].(string)), 255, "sub is at most 255 ASCII characters (§2)")
	if nonce != "" {
		require.Equal(b.t, nonce, claims["nonce"], "nonce is echoed (§3.1.3.7 step 11)")
	}
	return claims
}

// verifyAccessToken checks a JWT access token as a resource server does
// (RFC 9068 §4), with ShieldGate itself as the resource server, and returns
// its claims
func (b *browser) verifyAccessToken(raw string) jwt.MapClaims {
	b.t.Helper()
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(raw, claims, b.jwksKeyfunc(),
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(b.base),
		jwt.WithAudience(b.base),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(5*time.Second),
	)
	require.NoError(b.t, err, "access token must verify")
	require.Equal(b.t, "at+jwt", token.Header["typ"], "RFC 9068 §2.1")
	for _, claim := range []string{"sub", "client_id", "jti"} {
		require.NotEmpty(b.t, claims[claim], "RFC 9068 §2.2: %s", claim)
	}
	return claims
}

// jwksKeyfunc verifies tokens with the key named by kid in the JWKS
func (b *browser) jwksKeyfunc() jwt.Keyfunc {
	keys := b.signingKeys()
	return func(token *jwt.Token) (interface{}, error) {
		kid, _ := token.Header["kid"].(string)
		key, ok := keys[kid]
		if !ok {
			return nil, fmt.Errorf("no JWKS key for kid %q", kid)
		}
		return key, nil
	}
}

// signingKeys fetches the JWKS advertised by discovery
func (b *browser) signingKeys() map[string]*rsa.PublicKey {
	b.t.Helper()
	jwksURI, _ := b.get("/.well-known/openid-configuration", nil).json(b.t)["jwks_uri"].(string)
	require.NotEmpty(b.t, jwksURI)
	resp, err := b.client.Get(jwksURI)
	require.NoError(b.t, err)
	defer resp.Body.Close()
	var set struct {
		Keys []map[string]interface{} `json:"keys"`
	}
	require.NoError(b.t, json.NewDecoder(resp.Body).Decode(&set))
	keys := map[string]*rsa.PublicKey{}
	for _, k := range set.Keys {
		if k["kty"] != "RSA" {
			continue
		}
		n, errN := base64.RawURLEncoding.DecodeString(k["n"].(string))
		e, errE := base64.RawURLEncoding.DecodeString(k["e"].(string))
		require.NoError(b.t, errN)
		require.NoError(b.t, errE)
		kid, _ := k["kid"].(string)
		keys[kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	}
	require.NotEmpty(b.t, keys, "JWKS has an RSA key")
	return keys
}

// leftHalfHash is the at_hash / c_hash of value for RS256 (OIDC Core §3.1.3.6)
func leftHalfHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
}
