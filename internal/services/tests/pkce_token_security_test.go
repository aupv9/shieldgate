package tests

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"shieldgate/internal/services"
	"shieldgate/tests/utils"
)

// newTestAuthService creates an auth service with nil repos (safe for pure functions).
func newTestAuthService() services.AuthService {
	cfg := utils.CreateTestConfig()
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel) // silence logs in tests
	return services.NewAuthService(nil, cfg, logger)
}

// s256Challenge computes a valid S256 code challenge from a verifier.
func s256Challenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// ---- ValidatePKCE tests ----

func TestValidatePKCE_ValidS256(t *testing.T) {
	svc := newTestAuthService()
	verifier := strings.Repeat("a", 43) // minimum length
	challenge := s256Challenge(verifier)
	assert.True(t, svc.ValidatePKCE(verifier, challenge, "S256"))
}

func TestValidatePKCE_WrongVerifier(t *testing.T) {
	svc := newTestAuthService()
	verifier := strings.Repeat("a", 43)
	challenge := s256Challenge(verifier)
	assert.False(t, svc.ValidatePKCE("wrong-verifier", challenge, "S256"))
}

func TestValidatePKCE_PlainMethodRejected(t *testing.T) {
	// Server only supports S256; plain must be rejected
	svc := newTestAuthService()
	verifier := strings.Repeat("a", 43)
	assert.False(t, svc.ValidatePKCE(verifier, verifier, "plain"))
}

func TestValidatePKCE_UnsupportedMethod(t *testing.T) {
	svc := newTestAuthService()
	verifier := strings.Repeat("a", 43)
	challenge := s256Challenge(verifier)
	assert.False(t, svc.ValidatePKCE(verifier, challenge, "RS256"))
	assert.False(t, svc.ValidatePKCE(verifier, challenge, ""))
}

func TestValidatePKCE_ShortVerifier(t *testing.T) {
	// RFC 7636: verifier must be 43-128 characters; a short verifier will simply not match
	svc := newTestAuthService()
	shortVerifier := "tooshort"
	challenge := s256Challenge(shortVerifier)
	// Even with a matching challenge, a short verifier should be flagged at the
	// authorization endpoint (not here) — but ValidatePKCE itself will still
	// return true for a matching pair. The important case: wrong challenge fails.
	assert.True(t, svc.ValidatePKCE(shortVerifier, challenge, "S256")) // correct pair always matches
	assert.False(t, svc.ValidatePKCE(shortVerifier, "wrongchallenge", "S256"))
}

func TestValidatePKCE_EmptyInputs(t *testing.T) {
	svc := newTestAuthService()
	assert.False(t, svc.ValidatePKCE("", "", "S256"))
	assert.False(t, svc.ValidatePKCE("", "", ""))
}

// ---- ValidateAccessToken tests ----

func TestValidateAccessToken_ValidToken(t *testing.T) {
	cfg := utils.CreateTestConfig()
	svc := services.NewAuthService(nil, cfg, logrus.New())

	userID := uuid.New()
	clientID := uuid.New()
	tenantID := uuid.New()
	token := utils.CreateTestJWT(cfg, userID, clientID, tenantID, "read")

	claims, err := svc.ValidateAccessToken(context.Background(), tenantID, token)
	require.NoError(t, err)
	assert.Equal(t, userID.String(), claims.UserID)
	assert.Equal(t, tenantID.String(), claims.TenantID)
}

func TestValidateAccessToken_ExpiredToken(t *testing.T) {
	cfg := utils.CreateTestConfig()
	svc := services.NewAuthService(nil, cfg, logrus.New())

	tenantID := uuid.New()
	token := utils.CreateExpiredJWT(cfg, uuid.New(), uuid.New(), tenantID)

	_, err := svc.ValidateAccessToken(context.Background(), tenantID, token)
	assert.Error(t, err)
}

func TestValidateAccessToken_TamperedSignature(t *testing.T) {
	cfg := utils.CreateTestConfig()
	svc := services.NewAuthService(nil, cfg, logrus.New())

	tenantID := uuid.New()
	token := utils.CreateTamperedJWT(cfg, uuid.New(), uuid.New(), tenantID)

	_, err := svc.ValidateAccessToken(context.Background(), tenantID, token)
	assert.Error(t, err)
}

func TestValidateAccessToken_WrongTenant(t *testing.T) {
	cfg := utils.CreateTestConfig()
	svc := services.NewAuthService(nil, cfg, logrus.New())

	realTenantID := uuid.New()
	wrongTenantID := uuid.New()
	token := utils.CreateTestJWT(cfg, uuid.New(), uuid.New(), realTenantID, "read")

	// Token is valid but belongs to a different tenant
	_, err := svc.ValidateAccessToken(context.Background(), wrongTenantID, token)
	assert.Error(t, err)
}

func TestValidateAccessToken_MalformedToken(t *testing.T) {
	cfg := utils.CreateTestConfig()
	svc := services.NewAuthService(nil, cfg, logrus.New())

	tenantID := uuid.New()
	_, err := svc.ValidateAccessToken(context.Background(), tenantID, "not.a.jwt")
	assert.Error(t, err)
}

func TestValidateAccessToken_EmptyToken(t *testing.T) {
	cfg := utils.CreateTestConfig()
	svc := services.NewAuthService(nil, cfg, logrus.New())

	_, err := svc.ValidateAccessToken(context.Background(), uuid.New(), "")
	assert.Error(t, err)
}
