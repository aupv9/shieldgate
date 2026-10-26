//go:build integration

package gorm_test

// Integration tests for the email repositories against a real PostgreSQL.
// Run with:
//
//	SHIELDGATE_TEST_DATABASE_URL=postgres://... go test -tags integration ./internal/repo/gorm/

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"shieldgate/internal/database"
	"shieldgate/internal/models"
	gormrepo "shieldgate/internal/repo/gorm"
)

func openTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("SHIELDGATE_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("SHIELDGATE_TEST_DATABASE_URL not set")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(t, err)
	// Migrations must be idempotent: run them twice
	require.NoError(t, database.Migrate(db))
	require.NoError(t, database.Migrate(db))
	return db
}

func TestIntegration_UserWithAccountColumns_RoundTrips(t *testing.T) {
	// Arrange
	db := openTestDB(t)
	repos := gormrepo.NewRepositories(db)
	ctx := context.Background()
	until := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	user := &models.User{
		ID: uuid.New(), TenantID: uuid.New(), Username: "it-" + uuid.NewString(), Email: uuid.NewString() + "@example.com",
		PasswordHash: "x", Status: models.UserStatusLocked, EmailVerified: true, FailedLoginAttempts: 5, LockedUntil: &until,
	}

	// Act
	require.NoError(t, repos.User.Create(ctx, user))
	got, err := repos.User.GetByID(ctx, user.TenantID, user.ID)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, models.UserStatusLocked, got.Status)
	assert.True(t, got.EmailVerified)
	assert.Equal(t, 5, got.FailedLoginAttempts)
	require.NotNil(t, got.LockedUntil)
	assert.True(t, until.Equal(got.LockedUntil.UTC()))
}

func TestIntegration_PasswordReset_SingleUseUnderConcurrency(t *testing.T) {
	// Arrange
	db := openTestDB(t)
	resets := gormrepo.NewPasswordResetRepository(db)
	ctx := context.Background()
	reset := &models.PasswordReset{
		ID: uuid.New(), TenantID: uuid.New(), UserID: uuid.New(),
		TokenHash: uuid.NewString(), ExpiresAt: time.Now().Add(time.Hour),
	}
	require.NoError(t, resets.Create(ctx, reset))

	// Act
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := resets.MarkUsed(ctx, reset.ID)
			assert.NoError(t, err)
			if ok {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	// Assert
	assert.Equal(t, 1, wins)
	got, err := resets.GetByTokenHash(ctx, reset.TenantID, reset.TokenHash)
	require.NoError(t, err)
	assert.True(t, got.IsUsed())
}

func TestIntegration_PasswordReset_RevokeKeepsRowsForRateLimit(t *testing.T) {
	// Arrange
	db := openTestDB(t)
	resets := gormrepo.NewPasswordResetRepository(db)
	ctx := context.Background()
	tenantID, userID := uuid.New(), uuid.New()
	for i := 0; i < 2; i++ {
		require.NoError(t, resets.Create(ctx, &models.PasswordReset{
			ID: uuid.New(), TenantID: tenantID, UserID: userID,
			TokenHash: uuid.NewString(), ExpiresAt: time.Now().Add(time.Hour),
		}))
	}

	// Act
	require.NoError(t, resets.RevokeUnusedByUserID(ctx, tenantID, userID))
	count, err := resets.CountSince(ctx, tenantID, userID, time.Now().Add(-time.Hour))

	// Assert
	require.NoError(t, err)
	assert.EqualValues(t, 2, count)
}

func TestIntegration_EmailVerification_LookupMarkAndDeletePending(t *testing.T) {
	// Arrange
	db := openTestDB(t)
	verifications := gormrepo.NewEmailVerificationRepository(db)
	ctx := context.Background()
	v := &models.EmailVerification{
		ID: uuid.New(), TenantID: uuid.New(), UserID: uuid.New(), Email: "a@example.com",
		CodeHash: uuid.NewString(), ExpiresAt: time.Now().Add(time.Hour),
	}
	require.NoError(t, verifications.Create(ctx, v))

	// Act
	_, otherTenantErr := verifications.GetByCodeHash(ctx, uuid.New(), v.CodeHash)
	first, err1 := verifications.MarkVerified(ctx, v.ID)
	second, err2 := verifications.MarkVerified(ctx, v.ID)
	require.NoError(t, verifications.DeletePendingByUserID(ctx, v.TenantID, v.UserID))
	_, getErr := verifications.GetByCodeHash(ctx, v.TenantID, v.CodeHash)

	// Assert
	assert.ErrorIs(t, otherTenantErr, models.ErrInvalidVerificationCode)
	require.NoError(t, err1)
	require.NoError(t, err2)
	assert.True(t, first)
	assert.False(t, second)
	assert.NoError(t, getErr, "verified rows are not pending, so they survive")
}

func TestIntegration_EmailQueue_ClaimIsExclusive(t *testing.T) {
	// Arrange
	db := openTestDB(t)
	queue := gormrepo.NewEmailQueueRepository(db)
	ctx := context.Background()
	require.NoError(t, db.Exec("DELETE FROM email_queue").Error)
	tenantID := uuid.New()
	for i := 0; i < 20; i++ {
		require.NoError(t, queue.Create(ctx, &models.EmailQueue{
			ID: uuid.New(), TenantID: tenantID, ToEmail: "q@example.com", FromEmail: "f@example.com",
			Subject: "s", Status: "pending", Priority: 5, MaxAttempts: 3, ScheduledAt: time.Now().Add(-time.Second),
		}))
	}
	require.NoError(t, queue.Create(ctx, &models.EmailQueue{
		ID: uuid.New(), TenantID: tenantID, ToEmail: "later@example.com", FromEmail: "f@example.com",
		Subject: "s", Status: "pending", Priority: 5, MaxAttempts: 3, ScheduledAt: time.Now().Add(time.Hour),
	}))

	// Act: four workers claim concurrently
	var wg sync.WaitGroup
	var mu sync.Mutex
	claimed := map[uuid.UUID]int{}
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			emails, err := queue.GetPendingEmails(ctx, 10)
			assert.NoError(t, err)
			mu.Lock()
			defer mu.Unlock()
			for _, e := range emails {
				assert.Equal(t, "sending", e.Status)
				claimed[e.ID]++
			}
		}()
	}
	wg.Wait()
	status, err := queue.GetQueueStatus(ctx, tenantID)

	// Assert
	require.NoError(t, err)
	assert.Len(t, claimed, 20, "every due email is claimed, the future one is not")
	for id, n := range claimed {
		assert.Equal(t, 1, n, "email %s claimed more than once", id)
	}
	assert.Equal(t, map[string]int{"sending": 20, "pending": 1}, status)
}

func TestIntegration_EmailTemplate_TenantScoped(t *testing.T) {
	// Arrange
	db := openTestDB(t)
	templates := gormrepo.NewEmailTemplateRepository(db)
	ctx := context.Background()
	tenantID := uuid.New()
	require.NoError(t, templates.Create(ctx, &models.EmailTemplate{
		ID: uuid.New(), TenantID: tenantID, Name: "password_reset", Subject: "Acme", IsActive: true,
	}))

	// Act
	own, ownErr := templates.GetByName(ctx, tenantID, "password_reset")
	_, otherErr := templates.GetByName(ctx, uuid.New(), "password_reset")

	// Assert
	require.NoError(t, ownErr)
	assert.Equal(t, "Acme", own.Subject)
	assert.ErrorIs(t, otherErr, models.ErrResourceNotFound)
}
