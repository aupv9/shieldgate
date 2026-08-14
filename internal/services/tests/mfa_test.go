package tests

// mfa_test.go covers the RFC 6238 TOTP implementation and the MFA
// enrollment/activation lifecycle.

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"shieldgate/internal/models"
	"shieldgate/internal/services"
)

// currentTOTP returns the code currently valid for a secret
func currentTOTP(t *testing.T, secret string) string {
	t.Helper()
	code, err := services.GenerateTOTPCode(secret, time.Now())
	require.NoError(t, err)
	return code
}

func TestTOTP_RFC6238Vectors(t *testing.T) {
	// RFC 6238 Appendix B vectors (SHA-1, 8 digits truncated to 6 here we use
	// the standard secret "12345678901234567890" base32-encoded)
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" // "12345678901234567890"

	// At T=59s (step 1) the RFC's 8-digit code is 94287082 → 6-digit 287082
	code, err := services.GenerateTOTPCode(secret, time.Unix(59, 0))
	require.NoError(t, err)
	assert.Equal(t, "287082", code)

	// At T=1111111109 the RFC's code is 07081804 → 081804
	code, err = services.GenerateTOTPCode(secret, time.Unix(1111111109, 0))
	require.NoError(t, err)
	assert.Equal(t, "081804", code)
}

func TestTOTP_ValidateWithSkewWindow(t *testing.T) {
	secret, err := services.GenerateTOTPSecret()
	require.NoError(t, err)

	now := time.Now()
	code, err := services.GenerateTOTPCode(secret, now)
	require.NoError(t, err)

	assert.True(t, services.ValidateTOTPCode(secret, code, now))
	assert.True(t, services.ValidateTOTPCode(secret, code, now.Add(30*time.Second)), "±1 step skew must be tolerated")
	assert.False(t, services.ValidateTOTPCode(secret, code, now.Add(90*time.Second)), "codes outside the window must fail")
	assert.False(t, services.ValidateTOTPCode(secret, "000000", now))
	assert.False(t, services.ValidateTOTPCode(secret, "12345", now), "wrong length must fail")
}

func TestMFA_EnrollActivateVerifyDisable(t *testing.T) {
	repos := newFakeRepositories()
	svc := services.NewUserService(repos, quietLogger())
	ctx := context.Background()
	tenantID := uuid.New()

	user := &models.User{ID: uuid.New(), TenantID: tenantID, Username: "bob", Email: "bob@example.com"}
	require.NoError(t, repos.User.Create(ctx, user))

	// Verify before enrollment fails
	assert.ErrorIs(t, svc.VerifyMFA(ctx, tenantID, user.ID, "123456"), models.ErrMFANotEnrolled)

	// Enroll: secret returned once with otpauth URI
	secret, uri, err := svc.EnrollMFA(ctx, tenantID, user.ID)
	require.NoError(t, err)
	assert.NotEmpty(t, secret)
	assert.Contains(t, uri, "otpauth://totp/")
	assert.Contains(t, uri, secret)

	// Activation requires a valid code
	assert.ErrorIs(t, svc.ActivateMFA(ctx, tenantID, user.ID, "000000"), models.ErrMFAInvalidCode)
	require.NoError(t, svc.ActivateMFA(ctx, tenantID, user.ID, currentTOTP(t, secret)))

	// Enabled: verify works, re-enroll rejected
	require.NoError(t, svc.VerifyMFA(ctx, tenantID, user.ID, currentTOTP(t, secret)))
	assert.ErrorIs(t, svc.VerifyMFA(ctx, tenantID, user.ID, "999999"), models.ErrMFAInvalidCode)
	_, _, err = svc.EnrollMFA(ctx, tenantID, user.ID)
	assert.ErrorIs(t, err, models.ErrMFAAlreadyActive)

	// Disable requires a valid code and clears the secret
	assert.ErrorIs(t, svc.DisableMFA(ctx, tenantID, user.ID, "000000"), models.ErrMFAInvalidCode)
	require.NoError(t, svc.DisableMFA(ctx, tenantID, user.ID, currentTOTP(t, secret)))
	assert.ErrorIs(t, svc.VerifyMFA(ctx, tenantID, user.ID, currentTOTP(t, secret)), models.ErrMFANotEnrolled)
}
