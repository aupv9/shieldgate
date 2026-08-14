package handlers

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const csrfCookieName = "sg_csrf"

// mfaStateTokenTTL bounds how long the TOTP step may take after the password step
const mfaStateTokenTTL = 5 * time.Minute

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

// newMFAStateToken mints a short-lived signed token proving the password step
// of a login succeeded, carrying the flow to the TOTP step without a session
func newMFAStateToken(secret string, userID uuid.UUID, ttl time.Duration) (string, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	payload := fmt.Sprintf("%s|%d|%s", userID.String(), time.Now().Add(ttl).Unix(),
		base64.RawURLEncoding.EncodeToString(nonce))
	encoded := base64.RawURLEncoding.EncodeToString([]byte(payload))
	return encoded + "." + signCSRFValue(secret, "mfa:"+encoded), nil
}

// validateMFAStateToken verifies the signature and expiry, returning the user
// the password step authenticated
func validateMFAStateToken(secret, token string) (uuid.UUID, bool) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return uuid.Nil, false
	}
	expected := signCSRFValue(secret, "mfa:"+parts[0])
	if !hmac.Equal([]byte(parts[1]), []byte(expected)) {
		return uuid.Nil, false
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return uuid.Nil, false
	}
	fields := strings.SplitN(string(payloadBytes), "|", 3)
	if len(fields) != 3 {
		return uuid.Nil, false
	}
	userID, err := uuid.Parse(fields[0])
	if err != nil {
		return uuid.Nil, false
	}
	exp, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return uuid.Nil, false
	}
	return userID, true
}
