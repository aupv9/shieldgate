//go:build integration

package gorm_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"shieldgate/internal/models"
	"shieldgate/internal/repo"
	gormrepo "shieldgate/internal/repo/gorm"
)

// newPendingMFA stores a pending authenticator and returns the repository,
// the record and a function that reloads it
func newPendingMFA(t *testing.T) (context.Context, repo.MFARepository, *models.UserMFA, func() *models.UserMFA) {
	t.Helper()
	mfaRepo := gormrepo.NewMFARepository(openTestDB(t))
	ctx := context.Background()
	m := &models.UserMFA{UserID: uuid.New(), TenantID: uuid.New(), TOTPSecret: "sealed"}
	require.NoError(t, mfaRepo.SavePending(ctx, m))
	reload := func() *models.UserMFA {
		got, err := mfaRepo.Get(ctx, m.TenantID, m.UserID)
		require.NoError(t, err)
		return got
	}
	return ctx, mfaRepo, m, reload
}

func TestIntegration_MFA_EnrollConfirmAndReplaceRules(t *testing.T) {
	// Arrange
	db := openTestDB(t)
	repo := gormrepo.NewMFARepository(db)
	ctx := context.Background()
	m := &models.UserMFA{UserID: uuid.New(), TenantID: uuid.New(), TOTPSecret: "sealed-1"}
	require.NoError(t, repo.SavePending(ctx, m))

	// Act
	replacePendingErr := repo.SavePending(ctx, &models.UserMFA{UserID: m.UserID, TenantID: m.TenantID, TOTPSecret: "sealed-2"})
	confirmErr := repo.Confirm(ctx, m.TenantID, m.UserID, 42, []string{"h1", "h2", "h3"})
	reconfirmErr := repo.Confirm(ctx, m.TenantID, m.UserID, 43, nil)
	replaceEnabledErr := repo.SavePending(ctx, &models.UserMFA{UserID: m.UserID, TenantID: m.TenantID, TOTPSecret: "sealed-3"})
	got, getErr := repo.Get(ctx, m.TenantID, m.UserID)
	count, countErr := repo.CountUnusedRecoveryCodes(ctx, m.TenantID, m.UserID)
	_, otherTenantErr := repo.Get(ctx, uuid.New(), m.UserID)

	// Assert
	require.NoError(t, replacePendingErr, "a pending enrollment can be restarted")
	require.NoError(t, confirmErr)
	assert.ErrorIs(t, reconfirmErr, models.ErrMFANotEnrolling)
	assert.ErrorIs(t, replaceEnabledErr, models.ErrMFAAlreadyEnabled)
	require.NoError(t, getErr)
	assert.True(t, got.Enabled())
	assert.Equal(t, "sealed-2", got.TOTPSecret)
	assert.EqualValues(t, 42, got.LastUsedStep)
	require.NoError(t, countErr)
	assert.EqualValues(t, 3, count)
	assert.ErrorIs(t, otherTenantErr, models.ErrMFANotEnabled)
}

func TestIntegration_MFA_UseStepIsMonotonicUnderConcurrency(t *testing.T) {
	// Arrange
	ctx, repo, m, reload := newPendingMFA(t)
	require.NoError(t, repo.Confirm(ctx, m.TenantID, m.UserID, 100, nil))

	// Act: ten requests replay the same code concurrently
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := repo.UseStep(ctx, m.TenantID, m.UserID, 101)
			assert.NoError(t, err)
			if ok {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	older, err := repo.UseStep(ctx, m.TenantID, m.UserID, 100)

	// Assert
	assert.Equal(t, 1, wins)
	require.NoError(t, err)
	assert.False(t, older, "an earlier step cannot be used after a later one")
	assert.EqualValues(t, 101, reload().LastUsedStep)
}

func TestIntegration_MFA_FailuresLockAndSuccessClears(t *testing.T) {
	// Arrange
	ctx, repo, m, reload := newPendingMFA(t)
	require.NoError(t, repo.Confirm(ctx, m.TenantID, m.UserID, 1, []string{"rc"}))
	lockUntil := time.Now().Add(15 * time.Minute).Truncate(time.Second)

	// Act
	for i := 0; i < 4; i++ {
		require.NoError(t, repo.RecordFailure(ctx, m.TenantID, m.UserID, 5, lockUntil))
	}
	beforeLimit := reload()
	require.NoError(t, repo.RecordFailure(ctx, m.TenantID, m.UserID, 5, lockUntil))
	atLimit := reload()
	used, err := repo.UseRecoveryCode(ctx, m.TenantID, m.UserID, "rc")
	require.NoError(t, err)
	afterSuccess := reload()
	reused, err := repo.UseRecoveryCode(ctx, m.TenantID, m.UserID, "rc")

	// Assert
	assert.Equal(t, 4, beforeLimit.FailedAttempts)
	assert.Nil(t, beforeLimit.LockedUntil)
	assert.Equal(t, 5, atLimit.FailedAttempts)
	require.NotNil(t, atLimit.LockedUntil)
	assert.True(t, lockUntil.Equal(atLimit.LockedUntil.Truncate(time.Second)))
	assert.True(t, used)
	assert.Zero(t, afterSuccess.FailedAttempts)
	assert.Nil(t, afterSuccess.LockedUntil)
	require.NoError(t, err)
	assert.False(t, reused)
}

func TestIntegration_MFA_ReplaceAndDelete(t *testing.T) {
	// Arrange
	ctx, repo, m, _ := newPendingMFA(t)
	require.NoError(t, repo.Confirm(ctx, m.TenantID, m.UserID, 1, []string{"old-1", "old-2"}))

	// Act
	require.NoError(t, repo.ReplaceRecoveryCodes(ctx, m.TenantID, m.UserID, []string{"new-1"}))
	oldUsed, _ := repo.UseRecoveryCode(ctx, m.TenantID, m.UserID, "old-1")
	require.NoError(t, repo.Delete(ctx, m.TenantID, m.UserID))
	_, getErr := repo.Get(ctx, m.TenantID, m.UserID)
	count, _ := repo.CountUnusedRecoveryCodes(ctx, m.TenantID, m.UserID)

	// Assert
	assert.False(t, oldUsed)
	assert.ErrorIs(t, getErr, models.ErrMFANotEnabled)
	assert.Zero(t, count)
}

func TestIntegration_SessionAndCode_AMRRoundTrips(t *testing.T) {
	// Arrange
	db := openTestDB(t)
	repos := gormrepo.NewRepositories(db)
	ctx := context.Background()
	tenantID, userID := uuid.New(), uuid.New()
	now := time.Now()
	session := &models.Session{ID: uuid.New(), TenantID: tenantID, UserID: userID, TokenHash: uuid.NewString(),
		AuthTime: now, AMR: models.StringArray{"pwd", "otp", "mfa"}, ExpiresAt: now.Add(time.Hour)}
	code := &models.AuthorizationCode{ID: uuid.New(), TenantID: tenantID, Code: uuid.NewString(), ClientID: uuid.New(),
		UserID: userID, RedirectURI: "https://app/cb", AuthTime: &now, AMR: models.StringArray{"pwd"}, ExpiresAt: now.Add(time.Minute)}

	// Act
	require.NoError(t, repos.Session.Create(ctx, session))
	require.NoError(t, repos.AuthCode.Create(ctx, code))
	gotSession, err1 := repos.Session.GetByTokenHash(ctx, tenantID, session.TokenHash)
	gotCode, err2 := repos.AuthCode.GetByCode(ctx, tenantID, code.Code)

	// Assert
	require.NoError(t, err1)
	require.NoError(t, err2)
	assert.Equal(t, models.StringArray{"pwd", "otp", "mfa"}, gotSession.AMR)
	assert.Equal(t, models.StringArray{"pwd"}, gotCode.AMR)
}
