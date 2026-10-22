package tests

// account_email_test.go covers roadmap 4.3: email verification and password
// reset flows in UserService.

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"shieldgate/internal/models"
	"shieldgate/internal/repo"
	"shieldgate/internal/services"
)

type fakeEmailVerificationRepo struct {
	mu   sync.Mutex
	rows map[uuid.UUID]*models.EmailVerification
}

func (r *fakeEmailVerificationRepo) Create(ctx context.Context, v *models.EmailVerification) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	stored := *v
	r.rows[v.ID] = &stored
	return nil
}

func (r *fakeEmailVerificationRepo) GetByCodeHash(ctx context.Context, tenantID uuid.UUID, hash string) (*models.EmailVerification, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, v := range r.rows {
		if v.TenantID == tenantID && v.CodeHash == hash {
			copied := *v
			return &copied, nil
		}
	}
	return nil, models.ErrInvalidVerificationCode
}

func (r *fakeEmailVerificationRepo) MarkVerified(ctx context.Context, id uuid.UUID) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v, ok := r.rows[id]
	if !ok || v.VerifiedAt != nil {
		return false, nil
	}
	now := time.Now()
	v.VerifiedAt = &now
	return true, nil
}

func (r *fakeEmailVerificationRepo) DeletePendingByUserID(ctx context.Context, tenantID, userID uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, v := range r.rows {
		if v.TenantID == tenantID && v.UserID == userID && v.VerifiedAt == nil {
			delete(r.rows, id)
		}
	}
	return nil
}

func (r *fakeEmailVerificationRepo) DeleteExpired(ctx context.Context) error { return nil }

func (r *fakeEmailVerificationRepo) expireAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, v := range r.rows {
		v.ExpiresAt = time.Now().Add(-time.Minute)
	}
}

type fakePasswordResetRepo struct {
	mu   sync.Mutex
	rows map[uuid.UUID]*models.PasswordReset
}

func (r *fakePasswordResetRepo) Create(ctx context.Context, p *models.PasswordReset) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	stored := *p
	stored.CreatedAt = time.Now()
	r.rows[p.ID] = &stored
	return nil
}

func (r *fakePasswordResetRepo) GetByTokenHash(ctx context.Context, tenantID uuid.UUID, hash string) (*models.PasswordReset, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, p := range r.rows {
		if p.TenantID == tenantID && p.TokenHash == hash {
			copied := *p
			return &copied, nil
		}
	}
	return nil, models.ErrInvalidVerificationCode
}

func (r *fakePasswordResetRepo) MarkUsed(ctx context.Context, id uuid.UUID) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.rows[id]
	if !ok || p.UsedAt != nil {
		return false, nil
	}
	now := time.Now()
	p.UsedAt = &now
	return true, nil
}

func (r *fakePasswordResetRepo) CountSince(ctx context.Context, tenantID, userID uuid.UUID, since time.Time) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var n int64
	for _, p := range r.rows {
		if p.TenantID == tenantID && p.UserID == userID && p.CreatedAt.After(since) {
			n++
		}
	}
	return n, nil
}

func (r *fakePasswordResetRepo) RevokeUnusedByUserID(ctx context.Context, tenantID, userID uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	for _, p := range r.rows {
		if p.TenantID == tenantID && p.UserID == userID && p.UsedAt == nil {
			p.UsedAt = &now
		}
	}
	return nil
}

func (r *fakePasswordResetRepo) DeleteExpired(ctx context.Context) error { return nil }

func (r *fakePasswordResetRepo) expireAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, p := range r.rows {
		p.ExpiresAt = time.Now().Add(-time.Minute)
	}
}

// sentEmail is one call to the fake email sender
type sentEmail struct {
	to, template string
	vars         map[string]string
}

type fakeEmailSender struct {
	mu   sync.Mutex
	sent []sentEmail
}

func (s *fakeEmailSender) SendTemplateEmail(ctx context.Context, tenantID uuid.UUID, toEmail, toName, templateName string, variables map[string]string, priority int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent = append(s.sent, sentEmail{to: toEmail, template: templateName, vars: variables})
	return nil
}

// last returns the most recent email with the given template
func (s *fakeEmailSender) last(t *testing.T, template string) sentEmail {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.sent) - 1; i >= 0; i-- {
		if s.sent[i].template == template {
			return s.sent[i]
		}
	}
	t.Fatalf("no %s email sent", template)
	return sentEmail{}
}

func (s *fakeEmailSender) count(template string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, e := range s.sent {
		if e.template == template {
			n++
		}
	}
	return n
}

const accountPassword = "original-pw-1"

type accountFixture struct {
	ctx           context.Context
	repos         *repo.Repositories
	users         services.UserService
	emails        *fakeEmailSender
	verifications *fakeEmailVerificationRepo
	resets        *fakePasswordResetRepo
	sessions      *fakeSessionRepo
	user          *models.User
}

func newAccountFixture(t *testing.T) *accountFixture {
	t.Helper()
	f := &accountFixture{
		ctx:           context.Background(),
		repos:         newFakeRepositories(),
		emails:        &fakeEmailSender{},
		verifications: &fakeEmailVerificationRepo{rows: map[uuid.UUID]*models.EmailVerification{}},
		resets:        &fakePasswordResetRepo{rows: map[uuid.UUID]*models.PasswordReset{}},
	}
	sessionService, sessionRepo := newSessionService(time.Hour)
	f.sessions = sessionRepo
	f.repos.Session = sessionRepo
	f.repos.EmailVerification = f.verifications
	f.repos.PasswordReset = f.resets
	f.users = services.NewUserService(f.repos, f.emails, "https://auth.example/", quietLogger())

	hash, err := bcrypt.GenerateFromPassword([]byte(accountPassword), bcrypt.MinCost)
	require.NoError(t, err)
	f.user = &models.User{
		ID: uuid.New(), TenantID: uuid.New(), Username: "carol", Email: "carol@example.com",
		PasswordHash: string(hash), Status: models.UserStatusPending,
	}
	require.NoError(t, f.repos.User.Create(f.ctx, f.user))
	_, _, err = sessionService.CreateSession(f.ctx, f.user.TenantID, f.user.ID, "", "")
	require.NoError(t, err)
	return f
}

// linkParam extracts a query parameter from a link sent by email
func linkParam(t *testing.T, link, name string) string {
	t.Helper()
	u, err := url.Parse(link)
	require.NoError(t, err)
	value := u.Query().Get(name)
	require.NotEmpty(t, value, "link %s has no %s", link, name)
	return value
}

func (f *accountFixture) sendVerification(t *testing.T) string {
	t.Helper()
	require.NoError(t, f.users.SendVerificationEmail(f.ctx, f.user.TenantID, f.user.ID))
	link := f.emails.last(t, string(models.EmailTemplateEmailVerification)).vars["verification_link"]
	assert.True(t, strings.HasPrefix(link, "https://auth.example/account/verify-email?"), link)
	return linkParam(t, link, "code")
}

func (f *accountFixture) requestReset(t *testing.T) string {
	t.Helper()
	require.NoError(t, f.users.RequestPasswordReset(f.ctx, f.user.TenantID, f.user.Email))
	link := f.emails.last(t, string(models.EmailTemplatePasswordReset)).vars["reset_link"]
	assert.True(t, strings.HasPrefix(link, "https://auth.example/account/reset-password?"), link)
	return linkParam(t, link, "token")
}

func (f *accountFixture) reload(t *testing.T) *models.User {
	t.Helper()
	user, err := f.repos.User.GetByID(f.ctx, f.user.TenantID, f.user.ID)
	require.NoError(t, err)
	return user
}

func TestVerifyEmail_ValidCode_VerifiesActivatesAndIsSingleUse(t *testing.T) {
	// Arrange
	f := newAccountFixture(t)
	code := f.sendVerification(t)

	// Act
	user, err := f.users.VerifyEmail(f.ctx, f.user.TenantID, code)
	_, reuseErr := f.users.VerifyEmail(f.ctx, f.user.TenantID, code)

	// Assert
	require.NoError(t, err)
	assert.True(t, user.EmailVerified)
	assert.Equal(t, models.UserStatusActive, f.reload(t).Status)
	assert.ErrorIs(t, reuseErr, models.ErrInvalidVerificationCode)
	for _, v := range f.verifications.rows {
		assert.NotEqual(t, code, v.CodeHash, "only the hash is stored")
	}
}

func TestVerifyEmail_Failures(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(f *accountFixture, code string) (tenantID uuid.UUID, submitted string)
		wantErr error
	}{
		{"expired", func(f *accountFixture, code string) (uuid.UUID, string) {
			f.verifications.expireAll()
			return f.user.TenantID, code
		}, models.ErrVerificationExpired},
		{"unknown code", func(f *accountFixture, code string) (uuid.UUID, string) {
			return f.user.TenantID, "not-a-code"
		}, models.ErrInvalidVerificationCode},
		{"other tenant", func(f *accountFixture, code string) (uuid.UUID, string) {
			return uuid.New(), code
		}, models.ErrInvalidVerificationCode},
		{"email changed since", func(f *accountFixture, code string) (uuid.UUID, string) {
			_, err := f.users.Update(f.ctx, f.user.TenantID, f.user.ID, &models.UpdateUserRequest{Email: "new@example.com"})
			if err != nil {
				panic(err)
			}
			return f.user.TenantID, code
		}, models.ErrInvalidVerificationCode},
		{"superseded by resend", func(f *accountFixture, code string) (uuid.UUID, string) {
			if err := f.users.SendVerificationEmail(f.ctx, f.user.TenantID, f.user.ID); err != nil {
				panic(err)
			}
			return f.user.TenantID, code
		}, models.ErrInvalidVerificationCode},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			f := newAccountFixture(t)
			tenantID, code := tt.prepare(f, f.sendVerification(t))

			// Act
			_, err := f.users.VerifyEmail(f.ctx, tenantID, code)

			// Assert
			assert.ErrorIs(t, err, tt.wantErr)
			assert.False(t, f.reload(t).EmailVerified)
		})
	}
}

func TestSendVerificationEmail_AlreadyVerified_Conflict(t *testing.T) {
	// Arrange
	f := newAccountFixture(t)
	_, err := f.users.VerifyEmail(f.ctx, f.user.TenantID, f.sendVerification(t))
	require.NoError(t, err)

	// Act
	err = f.users.SendVerificationEmail(f.ctx, f.user.TenantID, f.user.ID)

	// Assert
	assert.ErrorIs(t, err, models.ErrEmailAlreadyVerified)
}

func TestResetPassword_ValidToken_ChangesPasswordAndRevokesEverything(t *testing.T) {
	// Arrange
	f := newAccountFixture(t)
	require.NoError(t, f.repos.AccessToken.Create(f.ctx, &models.AccessToken{ID: uuid.New(), TenantID: f.user.TenantID, UserID: f.user.ID, Token: "at"}))
	require.NoError(t, f.repos.RefreshToken.Create(f.ctx, &models.RefreshToken{ID: uuid.New(), TenantID: f.user.TenantID, UserID: f.user.ID, Token: "rt"}))
	token := f.requestReset(t)

	// Act
	_, err := f.users.ResetPassword(f.ctx, f.user.TenantID, token, "brand-new-pw-2")
	_, reuseErr := f.users.ResetPassword(f.ctx, f.user.TenantID, token, "another-pw-3")

	// Assert
	require.NoError(t, err)
	_, loginErr := f.users.Authenticate(f.ctx, f.user.TenantID, f.user.Email, "brand-new-pw-2")
	assert.NoError(t, loginErr)
	assert.ErrorIs(t, reuseErr, models.ErrInvalidVerificationCode, "tokens are single-use")
	assert.Equal(t, 0, f.sessions.count())
	_, atErr := f.repos.AccessToken.GetByToken(f.ctx, f.user.TenantID, "at")
	assert.Error(t, atErr, "access tokens are revoked")
	_, rtErr := f.repos.RefreshToken.GetByToken(f.ctx, f.user.TenantID, "rt")
	assert.Error(t, rtErr, "refresh tokens are revoked")
	assert.Equal(t, f.user.Email, f.emails.last(t, string(models.EmailTemplatePasswordChanged)).to)
}

func TestResetPassword_Failures_KeepOldPassword(t *testing.T) {
	tests := []struct {
		name     string
		prepare  func(f *accountFixture, token string) string
		password string
		wantErr  error
	}{
		{"expired", func(f *accountFixture, token string) string {
			f.resets.expireAll()
			return token
		}, "brand-new-pw-2", models.ErrVerificationExpired},
		{"unknown token", func(f *accountFixture, token string) string {
			return "not-a-token"
		}, "brand-new-pw-2", models.ErrInvalidVerificationCode},
		{"superseded by newer request", func(f *accountFixture, token string) string {
			if err := f.users.RequestPasswordReset(f.ctx, f.user.TenantID, f.user.Email); err != nil {
				panic(err)
			}
			return token
		}, "brand-new-pw-2", models.ErrInvalidVerificationCode},
		{"password too short", func(f *accountFixture, token string) string {
			return token
		}, "short", services.ErrPasswordTooShort},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			f := newAccountFixture(t)
			token := tt.prepare(f, f.requestReset(t))

			// Act
			_, err := f.users.ResetPassword(f.ctx, f.user.TenantID, token, tt.password)

			// Assert
			assert.ErrorIs(t, err, tt.wantErr)
			_, loginErr := f.users.Authenticate(f.ctx, f.user.TenantID, f.user.Email, accountPassword)
			assert.NoError(t, loginErr)
			assert.Equal(t, 1, f.sessions.count())
		})
	}
}

func TestResetPassword_TooShortPassword_DoesNotConsumeToken(t *testing.T) {
	// Arrange
	f := newAccountFixture(t)
	token := f.requestReset(t)
	_, err := f.users.ResetPassword(f.ctx, f.user.TenantID, token, "short")
	require.ErrorIs(t, err, services.ErrPasswordTooShort)

	// Act
	_, err = f.users.ResetPassword(f.ctx, f.user.TenantID, token, "long-enough-pw")

	// Assert
	assert.NoError(t, err)
}

func TestResetPassword_LockState(t *testing.T) {
	tests := []struct {
		name        string
		lockedUntil *time.Time
		wantStatus  models.UserStatus
	}{
		{"failed-login lockout is lifted", timePtr(time.Now().Add(time.Hour)), models.UserStatusActive},
		{"administrator lock stays", nil, models.UserStatusLocked},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			f := newAccountFixture(t)
			token := f.requestReset(t)
			user := f.reload(t)
			user.Status, user.LockedUntil, user.FailedLoginAttempts = models.UserStatusLocked, tt.lockedUntil, 5
			require.NoError(t, f.repos.User.Update(f.ctx, user))

			// Act
			_, err := f.users.ResetPassword(f.ctx, f.user.TenantID, token, "brand-new-pw-2")

			// Assert
			require.NoError(t, err)
			after := f.reload(t)
			assert.Equal(t, tt.wantStatus, after.Status)
			assert.Zero(t, after.FailedLoginAttempts)
		})
	}
}

func TestRequestPasswordReset_NoEmailSent(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(f *accountFixture) string
	}{
		{"unknown email", func(f *accountFixture) string { return "nobody@example.com" }},
		{"suspended user", func(f *accountFixture) string {
			user, _ := f.repos.User.GetByID(f.ctx, f.user.TenantID, f.user.ID)
			user.Status = models.UserStatusSuspended
			_ = f.repos.User.Update(f.ctx, user)
			return f.user.Email
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			f := newAccountFixture(t)
			email := tt.prepare(f)

			// Act
			err := f.users.RequestPasswordReset(f.ctx, f.user.TenantID, email)

			// Assert
			assert.NoError(t, err, "the response must not reveal whether the account exists")
			assert.Zero(t, f.emails.count(string(models.EmailTemplatePasswordReset)))
		})
	}
}

func TestRequestPasswordReset_RateLimitedPerUser(t *testing.T) {
	// Arrange
	f := newAccountFixture(t)

	// Act
	for i := 0; i < services.MaxPasswordResetsPerHour+2; i++ {
		require.NoError(t, f.users.RequestPasswordReset(f.ctx, f.user.TenantID, f.user.Email))
	}

	// Assert
	assert.Equal(t, services.MaxPasswordResetsPerHour, f.emails.count(string(models.EmailTemplatePasswordReset)))
}

func TestAccountEmails_WithoutEmailSender_Unavailable(t *testing.T) {
	// Arrange
	f := newAccountFixture(t)
	users := services.NewUserService(f.repos, nil, "https://auth.example", quietLogger())

	// Act
	verifyErr := users.SendVerificationEmail(f.ctx, f.user.TenantID, f.user.ID)
	resetErr := users.RequestPasswordReset(f.ctx, f.user.TenantID, f.user.Email)

	// Assert
	assert.Error(t, verifyErr)
	assert.Error(t, resetErr)
}

func timePtr(t time.Time) *time.Time { return &t }
