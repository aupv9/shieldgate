package handlers

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
)

const csrfCookieName = "sg_csrf"

// clientCredentialsFromRequest extracts OAuth client credentials from either
// the Authorization: Basic header (client_secret_basic, RFC 6749 §2.3.1 — the
// values are form-urlencoded before being base64-encoded) or the request body
// (client_secret_post). Returns ok=false when no client_id is present at all.
func clientCredentialsFromRequest(c *gin.Context) (clientID, clientSecret string, ok bool) {
	if user, pass, hasBasic := c.Request.BasicAuth(); hasBasic {
		clientID = user
		if decoded, err := url.QueryUnescape(user); err == nil {
			clientID = decoded
		}
		clientSecret = pass
		if decoded, err := url.QueryUnescape(pass); err == nil {
			clientSecret = decoded
		}
		return clientID, clientSecret, clientID != ""
	}

	clientID = c.PostForm("client_id")
	clientSecret = c.PostForm("client_secret")
	return clientID, clientSecret, clientID != ""
}

// newCSRFToken mints a random value signed with HMAC-SHA256 so the login form
// can be protected without server-side session state (signed double-submit
// cookie pattern: the token is stored in an HttpOnly cookie and echoed back in
// a hidden form field; a cross-site attacker can neither read nor set the cookie).
func newCSRFToken(secret string) (string, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	value := base64.RawURLEncoding.EncodeToString(nonce)
	return value + "." + signCSRFValue(secret, value), nil
}

// validateCSRFToken checks the form token against the cookie token and
// verifies the HMAC signature.
func validateCSRFToken(secret, formToken, cookieToken string) bool {
	if formToken == "" || cookieToken == "" {
		return false
	}
	if !hmac.Equal([]byte(formToken), []byte(cookieToken)) {
		return false
	}
	parts := strings.SplitN(formToken, ".", 2)
	if len(parts) != 2 {
		return false
	}
	expected := signCSRFValue(secret, parts[0])
	return hmac.Equal([]byte(parts[1]), []byte(expected))
}

func signCSRFValue(secret, value string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprint(mac, value)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
