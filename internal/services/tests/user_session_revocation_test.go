package tests

// user_session_revocation_test.go checks that account changes which must
// take effect in the browser end the user's SSO sessions.

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"shieldgate/internal/models"
	"shieldgate/internal/services"
)

const revocationPassword = "old-password-1"

type revocationFixture struct {
	ctx      context.Context
	users    services.UserService
	sessions services.SessionService
	repo     *fakeSessionRepo
	user     *models.User
}

// newRevocationFixture creates an active user with one live session
func newRevocationFixture(t *testing.T) *revocationFixture {
	t.Helper()
	ctx := context.Background()
	repos := newFakeRepositories()
	sessions, sessionRepo := newSessionService(time.Hour)
	repos.Session = sessionRepo

	hash, err := bcrypt.GenerateFromPassword([]byte(revocationPassword), bcrypt.MinCost)
	require.NoError(t, err)
	user := &models.User{
		ID: uuid.New(), TenantID: uuid.New(), Email: "bob@example.com",
		PasswordHash: string(hash), Status: models.UserStatusActive,
	}
	require.NoError(t, repos.User.Create(ctx, user))
	_, _, err = sessions.CreateSession(ctx, user.TenantID, user.ID, "", "")
	require.NoError(t, err)

	return &revocationFixture{
		ctx:      ctx,
		users:    services.NewUserService(repos, nil, "https://auth.example", quietLogger()),
		sessions: sessions,
		repo:     sessionRepo,
		user:     user,
	}
}

func TestUserService_AccountChanges_EndSessions(t *testing.T) {
	tests := []struct {
		name   string
		action func(f *revocationFixture) error
	}{
		{"suspend", func(f *revocationFixture) error {
			return f.users.SuspendUser(f.ctx, f.user.TenantID, f.user.ID, "abuse")
		}},
		{"lock", func(f *revocationFixture) error {
			return f.users.LockUser(f.ctx, f.user.TenantID, f.user.ID, "admin", nil)
		}},
		{"delete", func(f *revocationFixture) error {
			return f.users.Delete(f.ctx, f.user.TenantID, f.user.ID)
		}},
		{"change password", func(f *revocationFixture) error {
			return f.users.ChangePassword(f.ctx, f.user.TenantID, f.user.ID, revocationPassword, "new-password-2")
		}},
		{"update password", func(f *revocationFixture) error {
			_, err := f.users.Update(f.ctx, f.user.TenantID, f.user.ID, &models.UpdateUserRequest{Password: "new-password-2"})
			return err
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			f := newRevocationFixture(t)

			// Act
			err := tt.action(f)

			// Assert
			require.NoError(t, err)
			assert.Equal(t, 0, f.repo.count())
		})
	}
}

func TestUserService_FailedLoginLockout_KeepsSessions(t *testing.T) {
	// Arrange
	f := newRevocationFixture(t)

	// Act
	for i := 0; i < services.MaxLoginAttempts; i++ {
		_, _ = f.users.Authenticate(f.ctx, f.user.TenantID, f.user.Email, "wrong")
	}

	// Assert
	locked, err := f.users.GetByID(f.ctx, f.user.TenantID, f.user.ID)
	require.NoError(t, err)
	assert.True(t, locked.IsLocked())
	assert.Equal(t, 1, f.repo.count(), "guessing passwords must not sign the real user out")
}

func TestUserService_ProfileUpdateWithoutPassword_KeepsSessions(t *testing.T) {
	// Arrange
	f := newRevocationFixture(t)

	// Act
	_, err := f.users.Update(f.ctx, f.user.TenantID, f.user.ID, &models.UpdateUserRequest{Username: "bobby"})

	// Assert
	require.NoError(t, err)
	assert.Equal(t, 1, f.repo.count())
}
