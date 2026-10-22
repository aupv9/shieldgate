package tests

// mfa_service_test.go covers roadmap 4.1: TOTP enrollment, verification,
// replay and brute-force protection, recovery codes, and amr in ID tokens.

import (
	"context"
	"encoding/base32"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"shieldgate/internal/mfa"
	"shieldgate/internal/models"
	"shieldgate/internal/repo"
	"shieldgate/internal/services"
)

// fakeMFARepo mirrors the GORM repository's semantics in memory
type fakeMFARepo struct {
	mu    sync.Mutex
	rows  map[uuid.UUID]*models.UserMFA
	codes map[uuid.UUID][]*models.MFARecoveryCode
	now   func() time.Time
}

func newFakeMFARepo(now func() time.Time) *fakeMFARepo {
	return &fakeMFARepo{rows: map[uuid.UUID]*models.UserMFA{}, codes: map[uuid.UUID][]*models.MFARecoveryCode{}, now: now}
}

func (r *fakeMFARepo) Get(ctx context.Context, tenantID, userID uuid.UUID) (*models.UserMFA, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if row, ok := r.rows[userID]; ok && row.TenantID == tenantID {
		copied := *row
		return &copied, nil
	}
	return nil, models.ErrMFANotEnabled
}

func (r *fakeMFARepo) SavePending(ctx context.Context, m *models.UserMFA) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if row, ok := r.rows[m.UserID]; ok && row.Enabled() {
		return models.ErrMFAAlreadyEnabled
	}
	stored := *m
	stored.CreatedAt, stored.UpdatedAt = r.now(), r.now()
	r.rows[m.UserID] = &stored
	return nil
}

func (r *fakeMFARepo) Confirm(ctx context.Context, tenantID, userID uuid.UUID, step int64, hashes []string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	row, ok := r.rows[userID]
	if !ok || row.Enabled() {
		return models.ErrMFANotEnrolling
	}
	now := r.now()
	row.ConfirmedAt, row.LastUsedStep = &now, step
	r.replace(tenantID, userID, hashes)
	return nil
}

func (r *fakeMFARepo) UseStep(ctx context.Context, tenantID, userID uuid.UUID, step int64) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	row := r.rows[userID]
	if row == nil || !row.Enabled() || row.LastUsedStep >= step {
		return false, nil
	}
	row.LastUsedStep, row.FailedAttempts, row.LockedUntil = step, 0, nil
	return true, nil
}

func (r *fakeMFARepo) UseRecoveryCode(ctx context.Context, tenantID, userID uuid.UUID, hash string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.codes[userID] {
		if c.CodeHash == hash && c.UsedAt == nil {
			now := r.now()
			c.UsedAt = &now
			row := r.rows[userID]
			row.FailedAttempts, row.LockedUntil = 0, nil
			return true, nil
		}
	}
	return false, nil
}

func (r *fakeMFARepo) RecordFailure(ctx context.Context, tenantID, userID uuid.UUID, max int, lockUntil time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	row := r.rows[userID]
	row.FailedAttempts++
	if row.FailedAttempts >= max {
		row.LockedUntil = &lockUntil
	}
	return nil
}

func (r *fakeMFARepo) ReplaceRecoveryCodes(ctx context.Context, tenantID, userID uuid.UUID, hashes []string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.replace(tenantID, userID, hashes)
	return nil
}

func (r *fakeMFARepo) replace(tenantID, userID uuid.UUID, hashes []string) {
	r.codes[userID] = nil
	for _, h := range hashes {
		r.codes[userID] = append(r.codes[userID], &models.MFARecoveryCode{ID: uuid.New(), TenantID: tenantID, UserID: userID, CodeHash: h})
	}
}

func (r *fakeMFARepo) CountUnusedRecoveryCodes(ctx context.Context, tenantID, userID uuid.UUID) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var n int64
	for _, c := range r.codes[userID] {
		if c.UsedAt == nil {
			n++
		}
	}
	return n, nil
}

func (r *fakeMFARepo) Delete(ctx context.Context, tenantID, userID uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.rows, userID)
	delete(r.codes, userID)
	return nil
}

// fakeTenantRepo holds tenants by ID
type fakeTenantRepo struct {
	tenants map[uuid.UUID]*models.Tenant
}

func newFakeTenantRepo() *fakeTenantRepo {
	return &fakeTenantRepo{tenants: map[uuid.UUID]*models.Tenant{}}
}

func (r *fakeTenantRepo) Create(ctx context.Context, t *models.Tenant) error {
	r.tenants[t.ID] = t
	return nil
}

func (r *fakeTenantRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.Tenant, error) {
	if t, ok := r.tenants[id]; ok {
		return t, nil
	}
	return nil, models.ErrTenantNotFound
}

func (r *fakeTenantRepo) GetByDomain(ctx context.Context, domain string) (*models.Tenant, error) {
	return nil, models.ErrTenantNotFound
}

func (r *fakeTenantRepo) Update(ctx context.Context, t *models.Tenant) error { return r.Create(ctx, t) }

func (r *fakeTenantRepo) Delete(ctx context.Context, id uuid.UUID) error {
	delete(r.tenants, id)
	return nil
}

func (r *fakeTenantRepo) List(ctx context.Context, limit, offset int) ([]*models.Tenant, int64, error) {
	return nil, 0, nil
}

type mfaFixture struct {
	ctx        context.Context
	now        time.Time
	svc        services.MFAService
	repo       *fakeMFARepo
	repos      *repo.Repositories
	sessionSvc services.SessionService
	sessions   *fakeSessionRepo
	user       *models.User
}

func newMFAFixture(t *testing.T) *mfaFixture {
	t.Helper()
	f := &mfaFixture{ctx: context.Background(), now: time.Unix(1_800_000_000, 0)}
	clock := func() time.Time { return f.now }
	f.repo = newFakeMFARepo(clock)
	f.repos = newFakeRepositories()
	f.repos.MFA = f.repo
	f.repos.Tenant = newFakeTenantRepo()
	f.sessionSvc, f.sessions = newSessionService(time.Hour)
	f.repos.Session = f.sessions
	keys, err := mfa.NewKeys(mfa.DeriveKey("mfa-test-master-secret-0123456789"))
	require.NoError(t, err)
	f.svc = services.NewMFAServiceWithClock(f.repos, keys, clock, quietLogger())

	f.user = &models.User{ID: uuid.New(), TenantID: uuid.New(), Email: "frank@example.com"}
	require.NoError(t, f.repos.User.Create(f.ctx, f.user))
	require.NoError(t, f.repos.Tenant.Create(f.ctx, &models.Tenant{ID: f.user.TenantID, Name: "Acme"}))
	return f
}

// secretOf decodes the enrollment secret, checking the URI carries it
func secretOf(t *testing.T, e *models.TOTPEnrollment) []byte {
	t.Helper()
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(e.Secret)
	require.NoError(t, err)
	assert.Contains(t, e.OTPAuthURI, "secret="+e.Secret)
	return secret
}

// codeAt returns the TOTP code for the fixture clock shifted by offset steps
func (f *mfaFixture) codeAt(secret []byte, offset int64) string {
	return mfa.Code(secret, mfa.Step(f.now)+offset)
}

// enroll enables TOTP and returns the secret and recovery codes
func (f *mfaFixture) enroll(t *testing.T) ([]byte, []string) {
	t.Helper()
	enrollment, err := f.svc.BeginTOTPEnrollment(f.ctx, f.user.TenantID, f.user.ID)
	require.NoError(t, err)
	secret := secretOf(t, enrollment)
	codes, err := f.svc.ConfirmTOTPEnrollment(f.ctx, f.user.TenantID, f.user.ID, f.codeAt(secret, 0))
	require.NoError(t, err)
	// Later verifications happen in a later step than the confirming code
	f.now = f.now.Add(mfa.Period)
	return secret, codes
}

func TestMFA_Enroll_EnablesStoresSealedSecretAndEndsSessions(t *testing.T) {
	// Arrange
	f := newMFAFixture(t)
	_, _, err := f.sessionSvc.CreateSession(f.ctx, f.user.TenantID, f.user.ID, nil, "", "")
	require.NoError(t, err)
	enrollment, err := f.svc.BeginTOTPEnrollment(f.ctx, f.user.TenantID, f.user.ID)
	require.NoError(t, err)
	before, _ := f.svc.IsEnabled(f.ctx, f.user.TenantID, f.user.ID)

	// Act
	codes, err := f.svc.ConfirmTOTPEnrollment(f.ctx, f.user.TenantID, f.user.ID, f.codeAt(secretOf(t, enrollment), 0))

	// Assert
	require.NoError(t, err)
	assert.False(t, before, "pending enrollment does not enable MFA")
	status, _ := f.svc.Status(f.ctx, f.user.TenantID, f.user.ID)
	assert.True(t, status.Enabled)
	assert.Equal(t, []string{models.MFAMethodTOTP}, status.Methods)
	assert.Equal(t, mfa.RecoveryCodeCount, status.RecoveryCodesRemaining)
	assert.Len(t, codes, mfa.RecoveryCodeCount)
	assert.True(t, strings.HasPrefix(enrollment.OTPAuthURI, "otpauth://totp/Acme:frank@example.com?"), enrollment.OTPAuthURI)
	row := f.repo.rows[f.user.ID]
	assert.NotContains(t, row.TOTPSecret, enrollment.Secret, "the secret is stored encrypted")
	assert.Equal(t, 0, f.sessions.count(), "password-only sessions end when MFA is turned on")
}

func TestMFA_ConfirmFailures(t *testing.T) {
	tests := []struct {
		name    string
		act     func(f *mfaFixture, secret []byte) error
		wantErr error
	}{
		{"wrong code", func(f *mfaFixture, secret []byte) error {
			_, err := f.svc.ConfirmTOTPEnrollment(f.ctx, f.user.TenantID, f.user.ID, "000000")
			return err
		}, models.ErrInvalidMFACode},
		{"enrollment window passed", func(f *mfaFixture, secret []byte) error {
			f.now = f.now.Add(16 * time.Minute)
			_, err := f.svc.ConfirmTOTPEnrollment(f.ctx, f.user.TenantID, f.user.ID, f.codeAt(secret, 0))
			return err
		}, models.ErrMFANotEnrolling},
		{"other tenant", func(f *mfaFixture, secret []byte) error {
			_, err := f.svc.ConfirmTOTPEnrollment(f.ctx, uuid.New(), f.user.ID, f.codeAt(secret, 0))
			return err
		}, models.ErrMFANotEnrolling},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			f := newMFAFixture(t)
			enrollment, err := f.svc.BeginTOTPEnrollment(f.ctx, f.user.TenantID, f.user.ID)
			require.NoError(t, err)

			// Act
			err = tt.act(f, secretOf(t, enrollment))

			// Assert
			assert.ErrorIs(t, err, tt.wantErr)
			enabled, _ := f.svc.IsEnabled(f.ctx, f.user.TenantID, f.user.ID)
			assert.False(t, enabled)
		})
	}
}

func TestMFA_BeginWhenEnabled_Conflict(t *testing.T) {
	// Arrange
	f := newMFAFixture(t)
	f.enroll(t)

	// Act
	_, err := f.svc.BeginTOTPEnrollment(f.ctx, f.user.TenantID, f.user.ID)

	// Assert
	assert.ErrorIs(t, err, models.ErrMFAAlreadyEnabled, "replacing an authenticator requires disabling it first")
}

func TestMFA_VerifyTOTP_AcceptsOnceRejectsReplay(t *testing.T) {
	// Arrange
	f := newMFAFixture(t)
	secret, _ := f.enroll(t)
	code := f.codeAt(secret, 0)

	// Act
	method, err := f.svc.Verify(f.ctx, f.user.TenantID, f.user.ID, code)
	_, replayErr := f.svc.Verify(f.ctx, f.user.TenantID, f.user.ID, code)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, models.MFAMethodTOTP, method)
	assert.ErrorIs(t, replayErr, models.ErrInvalidMFACode, "an observed code cannot be replayed")
}

func TestMFA_VerifyTOTP_ToleratesOneStepOfDrift(t *testing.T) {
	// Arrange
	f := newMFAFixture(t)
	secret, _ := f.enroll(t)
	f.now = f.now.Add(mfa.Period)

	// Act
	_, err := f.svc.Verify(f.ctx, f.user.TenantID, f.user.ID, f.codeAt(secret, -1))

	// Assert
	assert.NoError(t, err)
}

func TestMFA_RecoveryCode_SingleUseAndForgivingInput(t *testing.T) {
	// Arrange
	f := newMFAFixture(t)
	_, codes := f.enroll(t)
	typed := strings.ToLower(strings.ReplaceAll(codes[0], "-", ""))

	// Act
	method, err := f.svc.Verify(f.ctx, f.user.TenantID, f.user.ID, typed)
	_, reuseErr := f.svc.Verify(f.ctx, f.user.TenantID, f.user.ID, codes[0])
	status, _ := f.svc.Status(f.ctx, f.user.TenantID, f.user.ID)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, models.MFAMethodRecoveryCode, method)
	assert.ErrorIs(t, reuseErr, models.ErrInvalidMFACode)
	assert.Equal(t, mfa.RecoveryCodeCount-1, status.RecoveryCodesRemaining)
}

func TestMFA_RepeatedFailures_LockEvenCorrectCodesUntilExpiry(t *testing.T) {
	// Arrange
	f := newMFAFixture(t)
	secret, _ := f.enroll(t)

	// Act
	var errs []error
	for i := 0; i < services.MaxMFAFailures; i++ {
		_, err := f.svc.Verify(f.ctx, f.user.TenantID, f.user.ID, "000000")
		errs = append(errs, err)
	}
	_, lockedErr := f.svc.Verify(f.ctx, f.user.TenantID, f.user.ID, f.codeAt(secret, 0))
	f.now = f.now.Add(services.MFALockoutDuration + time.Second)
	_, afterErr := f.svc.Verify(f.ctx, f.user.TenantID, f.user.ID, f.codeAt(secret, 0))

	// Assert
	for _, err := range errs[:len(errs)-1] {
		assert.ErrorIs(t, err, models.ErrInvalidMFACode)
	}
	assert.ErrorIs(t, errs[len(errs)-1], models.ErrMFALocked)
	assert.ErrorIs(t, lockedErr, models.ErrMFALocked, "a correct code does not bypass the lock")
	assert.NoError(t, afterErr)
}

func TestMFA_RegenerateRecoveryCodes_InvalidatesOld(t *testing.T) {
	// Arrange
	f := newMFAFixture(t)
	_, oldCodes := f.enroll(t)

	// Act
	newCodes, err := f.svc.RegenerateRecoveryCodes(f.ctx, f.user.TenantID, f.user.ID)
	_, oldErr := f.svc.Verify(f.ctx, f.user.TenantID, f.user.ID, oldCodes[0])
	_, newErr := f.svc.Verify(f.ctx, f.user.TenantID, f.user.ID, newCodes[0])

	// Assert
	require.NoError(t, err)
	assert.ErrorIs(t, oldErr, models.ErrInvalidMFACode)
	assert.NoError(t, newErr)
}

func TestMFA_Disable_RemovesFactorAndEndsSessions(t *testing.T) {
	// Arrange
	f := newMFAFixture(t)
	f.enroll(t)
	_, _, err := f.sessionSvc.CreateSession(f.ctx, f.user.TenantID, f.user.ID, []string{"pwd", "otp", "mfa"}, "", "")
	require.NoError(t, err)

	// Act
	err = f.svc.Disable(f.ctx, f.user.TenantID, f.user.ID)

	// Assert
	require.NoError(t, err)
	enabled, _ := f.svc.IsEnabled(f.ctx, f.user.TenantID, f.user.ID)
	assert.False(t, enabled)
	assert.Equal(t, 0, f.sessions.count())
	_, verifyErr := f.svc.Verify(f.ctx, f.user.TenantID, f.user.ID, "000000")
	assert.ErrorIs(t, verifyErr, models.ErrMFANotEnabled)
}

func TestAMRForSecondFactor(t *testing.T) {
	assert.Equal(t, []string{"pwd", "otp", "mfa"}, services.AMRForSecondFactor(models.MFAMethodTOTP))
	assert.Equal(t, []string{"pwd", "mfa"}, services.AMRForSecondFactor(models.MFAMethodRecoveryCode))
}

func TestIDToken_AMR_FromCodeAndKeptOnRefresh(t *testing.T) {
	// Arrange
	f := newOIDCFixture(t)
	ctx := context.Background()
	amr := []string{"pwd", "otp", "mfa"}
	code, err := f.svc.GenerateAuthorizationCode(ctx, f.tenantID, f.client.ID, f.user.ID, "https://app/cb", "openid", "", "", "", time.Now(), amr)
	require.NoError(t, err)

	// Act
	tokens, err := f.svc.ExchangeAuthorizationCode(ctx, f.tenantID, code.Code, f.client.ID.String(), "", "https://app/cb", "")
	require.NoError(t, err)
	refreshed, err := f.svc.RefreshTokens(ctx, f.tenantID, tokens.RefreshToken, f.client.ID.String(), "")
	require.NoError(t, err)

	// Assert
	assert.Equal(t, []interface{}{"pwd", "otp", "mfa"}, f.idClaims(t, tokens.IDToken)["amr"])
	assert.Equal(t, []interface{}{"pwd", "otp", "mfa"}, f.idClaims(t, refreshed.IDToken)["amr"], "refresh keeps the original authentication methods")
}

func TestIDToken_NoAMR_ClaimOmitted(t *testing.T) {
	// Arrange
	f := newOIDCFixture(t)

	// Act
	tokens := f.exchange(t, "openid", "", time.Now())

	// Assert
	assert.NotContains(t, f.idClaims(t, tokens.IDToken), "amr")
}
