package services

import (
	"context"
	"errors"
	"fmt"
	"time"

	"shieldgate/internal/mfa"
	"shieldgate/internal/models"
	"shieldgate/internal/repo"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

const (
	// MaxMFAFailures is how many wrong codes lock second-factor verification
	MaxMFAFailures = 5
	// MFALockoutDuration is how long verification stays locked
	MFALockoutDuration = 15 * time.Minute
	// mfaEnrollmentWindow is how long a started enrollment can be confirmed
	mfaEnrollmentWindow = 15 * time.Minute
	// defaultMFAIssuer names the account in authenticator apps when the
	// tenant has no name
	defaultMFAIssuer = "ShieldGate"
)

// Authentication method references (RFC 8176) for the amr claim
const (
	AMRPassword = "pwd"
	AMROTP      = "otp"
	AMRMFA      = "mfa"
)

// AMRForSecondFactor returns the amr values of a password login completed
// with the given MFA method
func AMRForSecondFactor(method string) []string {
	if method == models.MFAMethodTOTP {
		return []string{AMRPassword, AMROTP, AMRMFA}
	}
	return []string{AMRPassword, AMRMFA}
}

type mfaServiceImpl struct {
	repos  *repo.Repositories
	keys   *mfa.Keys
	now    func() time.Time
	logger *logrus.Logger
}

// NewMFAService creates the TOTP multi-factor authentication service
func NewMFAService(repos *repo.Repositories, keys *mfa.Keys, logger *logrus.Logger) MFAService {
	return &mfaServiceImpl{repos: repos, keys: keys, now: time.Now, logger: logger}
}

// NewMFAServiceWithClock is NewMFAService with a controllable clock, for tests
func NewMFAServiceWithClock(repos *repo.Repositories, keys *mfa.Keys, now func() time.Time, logger *logrus.Logger) MFAService {
	return &mfaServiceImpl{repos: repos, keys: keys, now: now, logger: logger}
}

// secretAAD binds a sealed secret to its owner
func secretAAD(tenantID, userID uuid.UUID) string {
	return tenantID.String() + "|" + userID.String()
}

func (s *mfaServiceImpl) Status(ctx context.Context, tenantID, userID uuid.UUID) (*models.MFAStatus, error) {
	status := &models.MFAStatus{Methods: []string{}}
	settings, err := s.repos.MFA.Get(ctx, tenantID, userID)
	if errors.Is(err, models.ErrMFANotEnabled) {
		return status, nil
	}
	if err != nil {
		return nil, err
	}
	if !settings.Enabled() {
		return status, nil
	}
	remaining, err := s.repos.MFA.CountUnusedRecoveryCodes(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	status.Enabled = true
	status.Methods = []string{models.MFAMethodTOTP}
	status.EnabledAt = settings.ConfirmedAt
	status.RecoveryCodesRemaining = int(remaining)
	return status, nil
}

func (s *mfaServiceImpl) IsEnabled(ctx context.Context, tenantID, userID uuid.UUID) (bool, error) {
	settings, err := s.repos.MFA.Get(ctx, tenantID, userID)
	if errors.Is(err, models.ErrMFANotEnabled) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return settings.Enabled(), nil
}

func (s *mfaServiceImpl) BeginTOTPEnrollment(ctx context.Context, tenantID, userID uuid.UUID) (*models.TOTPEnrollment, error) {
	user, err := s.repos.User.GetByID(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}

	secret, err := mfa.NewSecret()
	if err != nil {
		return nil, fmt.Errorf("failed to generate TOTP secret: %w", err)
	}
	sealed, err := s.keys.Seal(secret, secretAAD(tenantID, userID))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt TOTP secret: %w", err)
	}
	if err := s.repos.MFA.SavePending(ctx, &models.UserMFA{
		UserID:     userID,
		TenantID:   tenantID,
		TOTPSecret: sealed,
	}); err != nil {
		return nil, err
	}

	issuer := defaultMFAIssuer
	if tenant, err := s.repos.Tenant.GetByID(ctx, tenantID); err == nil && tenant.Name != "" {
		issuer = tenant.Name
	}
	return &models.TOTPEnrollment{
		Secret:     mfa.EncodeSecret(secret),
		OTPAuthURI: mfa.KeyURI(issuer, user.Email, secret),
	}, nil
}

func (s *mfaServiceImpl) ConfirmTOTPEnrollment(ctx context.Context, tenantID, userID uuid.UUID, code string) ([]string, error) {
	settings, err := s.repos.MFA.Get(ctx, tenantID, userID)
	if errors.Is(err, models.ErrMFANotEnabled) {
		return nil, models.ErrMFANotEnrolling
	}
	if err != nil {
		return nil, err
	}
	if settings.Enabled() {
		return nil, models.ErrMFAAlreadyEnabled
	}
	if s.now().Sub(settings.UpdatedAt) > mfaEnrollmentWindow {
		return nil, models.ErrMFANotEnrolling
	}

	secret, err := s.keys.Open(settings.TOTPSecret, secretAAD(tenantID, userID))
	if err != nil {
		return nil, err
	}
	step, ok := mfa.Verify(secret, code, s.now())
	if !ok {
		return nil, models.ErrInvalidMFACode
	}

	codes, hashes, err := s.newRecoveryCodes()
	if err != nil {
		return nil, err
	}
	if err := s.repos.MFA.Confirm(ctx, tenantID, userID, step, hashes); err != nil {
		return nil, err
	}
	// Sessions opened with the password alone must not outlive the change
	if err := s.endSessions(ctx, tenantID, userID); err != nil {
		return nil, err
	}

	s.logger.WithFields(logrus.Fields{"tenant_id": tenantID, "user_id": userID}).Info("TOTP enabled")
	return codes, nil
}

// Verify checks a TOTP or recovery code and returns the method used. Wrong
// codes count towards a lockout that a correct password does not reset.
func (s *mfaServiceImpl) Verify(ctx context.Context, tenantID, userID uuid.UUID, code string) (string, error) {
	settings, err := s.repos.MFA.Get(ctx, tenantID, userID)
	if err != nil {
		return "", err
	}
	if !settings.Enabled() {
		return "", models.ErrMFANotEnabled
	}
	now := s.now()
	if settings.LockedUntil != nil && now.Before(*settings.LockedUntil) {
		return "", models.ErrMFALocked
	}

	method, ok, err := s.check(ctx, settings, code, now)
	if err != nil {
		return "", err
	}
	if ok {
		return method, nil
	}

	if err := s.repos.MFA.RecordFailure(ctx, tenantID, userID, MaxMFAFailures, now.Add(MFALockoutDuration)); err != nil {
		return "", err
	}
	s.logger.WithFields(logrus.Fields{"tenant_id": tenantID, "user_id": userID}).Warn("invalid MFA code")
	if settings.FailedAttempts+1 >= MaxMFAFailures {
		return "", models.ErrMFALocked
	}
	return "", models.ErrInvalidMFACode
}

// check verifies code without counting failures
func (s *mfaServiceImpl) check(ctx context.Context, settings *models.UserMFA, code string, now time.Time) (string, bool, error) {
	if mfa.LooksLikeTOTP(code) {
		secret, err := s.keys.Open(settings.TOTPSecret, secretAAD(settings.TenantID, settings.UserID))
		if err != nil {
			return "", false, err
		}
		step, ok := mfa.Verify(secret, code, now)
		if !ok {
			return "", false, nil
		}
		// A code is accepted once: replaying an observed code fails
		fresh, err := s.repos.MFA.UseStep(ctx, settings.TenantID, settings.UserID, step)
		return models.MFAMethodTOTP, fresh, err
	}

	used, err := s.repos.MFA.UseRecoveryCode(ctx, settings.TenantID, settings.UserID, s.keys.HashRecoveryCode(code))
	if used {
		s.logger.WithFields(logrus.Fields{"tenant_id": settings.TenantID, "user_id": settings.UserID}).Warn("recovery code used")
	}
	return models.MFAMethodRecoveryCode, used, err
}

func (s *mfaServiceImpl) RegenerateRecoveryCodes(ctx context.Context, tenantID, userID uuid.UUID) ([]string, error) {
	enabled, err := s.IsEnabled(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, models.ErrMFANotEnabled
	}
	codes, hashes, err := s.newRecoveryCodes()
	if err != nil {
		return nil, err
	}
	if err := s.repos.MFA.ReplaceRecoveryCodes(ctx, tenantID, userID, hashes); err != nil {
		return nil, err
	}
	return codes, nil
}

func (s *mfaServiceImpl) Disable(ctx context.Context, tenantID, userID uuid.UUID) error {
	if _, err := s.repos.MFA.Get(ctx, tenantID, userID); err != nil {
		return err
	}
	if err := s.repos.MFA.Delete(ctx, tenantID, userID); err != nil {
		return err
	}
	if err := s.endSessions(ctx, tenantID, userID); err != nil {
		return err
	}
	s.logger.WithFields(logrus.Fields{"tenant_id": tenantID, "user_id": userID}).Info("MFA disabled")
	return nil
}

func (s *mfaServiceImpl) newRecoveryCodes() ([]string, []string, error) {
	codes, err := mfa.NewRecoveryCodes()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate recovery codes: %w", err)
	}
	hashes := make([]string, len(codes))
	for i, code := range codes {
		hashes[i] = s.keys.HashRecoveryCode(code)
	}
	return codes, hashes, nil
}

func (s *mfaServiceImpl) endSessions(ctx context.Context, tenantID, userID uuid.UUID) error {
	if s.repos.Session == nil {
		return nil
	}
	if err := s.repos.Session.DeleteByUserID(ctx, tenantID, userID); err != nil {
		return fmt.Errorf("failed to end user sessions: %w", err)
	}
	return nil
}
