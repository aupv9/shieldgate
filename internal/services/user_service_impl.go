package services

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"shieldgate/internal/models"
	"shieldgate/internal/repo"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

var (
	// ErrPasswordTooShort is returned when a new password is shorter than
	// MinPasswordLength
	ErrPasswordTooShort = fmt.Errorf("password must be at least %d characters", MinPasswordLength)

	errAccountEmailsUnavailable = errors.New("account emails are not configured")
)

type userServiceImpl struct {
	repos  *repo.Repositories
	emails TemplateEmailSender
	// baseURL is the public server URL that email links point to
	baseURL string
	logger  *logrus.Logger
}

const (
	MaxLoginAttempts = 5
	LockoutDuration  = 30 * time.Minute

	// EmailVerificationDuration is how long a verification link stays valid
	EmailVerificationDuration = 24 * time.Hour
	// PasswordResetDuration is how long a reset link stays valid
	PasswordResetDuration = time.Hour
	// MaxPasswordResetsPerHour bounds reset emails per user, so the reset
	// form cannot be used to flood someone's inbox
	MaxPasswordResetsPerHour = 3
	// MinPasswordLength is the shortest password accepted on reset
	MinPasswordLength = 8

	// emailLinkTokenBytes is the entropy of verification codes and reset
	// tokens (256 bits)
	emailLinkTokenBytes = 32
)

// NewUserService creates a new user service implementation. emails may be
// nil, in which case account emails (verification, password reset) are
// unavailable; baseURL is the public URL that email links point to.
func NewUserService(repos *repo.Repositories, emails TemplateEmailSender, baseURL string, logger *logrus.Logger) UserService {
	return &userServiceImpl{
		repos:   repos,
		emails:  emails,
		baseURL: strings.TrimSuffix(baseURL, "/"),
		logger:  logger,
	}
}

func (s *userServiceImpl) Create(ctx context.Context, tenantID uuid.UUID, req *models.CreateUserRequest) (*models.User, error) {
	// Validate request
	if req.Username == "" {
		return nil, fmt.Errorf("username is required")
	}
	if req.Email == "" {
		return nil, fmt.Errorf("email is required")
	}
	if req.Password == "" {
		return nil, fmt.Errorf("password is required")
	}

	// Check if username already exists in tenant
	if _, err := s.repos.User.GetByUsername(ctx, tenantID, req.Username); err == nil {
		return nil, fmt.Errorf("username already exists")
	}

	// Check if email already exists in tenant
	if _, err := s.repos.User.GetByEmail(ctx, tenantID, req.Email); err == nil {
		return nil, fmt.Errorf("email already exists")
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create user
	user := &models.User{
		ID:           uuid.New(),
		TenantID:     tenantID,
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: string(hashedPassword),
	}

	if err := s.repos.User.Create(ctx, user); err != nil {
		s.logger.WithError(err).Error("failed to create user")
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"tenant_id": tenantID,
		"user_id":   user.ID,
		"username":  user.Username,
		"email":     user.Email,
	}).Info("user created successfully")

	return user, nil
}

func (s *userServiceImpl) GetByID(ctx context.Context, tenantID, userID uuid.UUID) (*models.User, error) {
	user, err := s.repos.User.GetByID(ctx, tenantID, userID)
	if err != nil {
		s.logger.WithError(err).WithFields(logrus.Fields{
			"tenant_id": tenantID,
			"user_id":   userID,
		}).Error("failed to get user by ID")
		return nil, err
	}
	return user, nil
}

func (s *userServiceImpl) GetByEmail(ctx context.Context, tenantID uuid.UUID, email string) (*models.User, error) {
	user, err := s.repos.User.GetByEmail(ctx, tenantID, email)
	if err != nil {
		s.logger.WithError(err).WithFields(logrus.Fields{
			"tenant_id": tenantID,
			"email":     email,
		}).Error("failed to get user by email")
		return nil, err
	}
	return user, nil
}

func (s *userServiceImpl) GetByUsername(ctx context.Context, tenantID uuid.UUID, username string) (*models.User, error) {
	user, err := s.repos.User.GetByUsername(ctx, tenantID, username)
	if err != nil {
		s.logger.WithError(err).WithFields(logrus.Fields{
			"tenant_id": tenantID,
			"username":  username,
		}).Error("failed to get user by username")
		return nil, err
	}
	return user, nil
}

func (s *userServiceImpl) Update(ctx context.Context, tenantID, userID uuid.UUID, req *models.UpdateUserRequest) (*models.User, error) {
	// Get existing user
	user, err := s.repos.User.GetByID(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}

	// Update fields
	if req.Username != "" && req.Username != user.Username {
		// Check if new username already exists
		if _, err := s.repos.User.GetByUsername(ctx, tenantID, req.Username); err == nil {
			return nil, fmt.Errorf("username already exists")
		}
		user.Username = req.Username
	}

	if req.Email != "" && req.Email != user.Email {
		// Check if new email already exists
		if _, err := s.repos.User.GetByEmail(ctx, tenantID, req.Email); err == nil {
			return nil, fmt.Errorf("email already exists")
		}
		user.Email = req.Email
	}

	if req.Password != "" {
		// Hash new password
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			return nil, fmt.Errorf("failed to hash password: %w", err)
		}
		user.PasswordHash = string(hashedPassword)
	}

	if err := s.repos.User.Update(ctx, user); err != nil {
		s.logger.WithError(err).WithFields(logrus.Fields{
			"tenant_id": tenantID,
			"user_id":   userID,
		}).Error("failed to update user")
		return nil, fmt.Errorf("failed to update user: %w", err)
	}
	if req.Password != "" {
		if err := s.endSessions(ctx, tenantID, userID); err != nil {
			return nil, err
		}
	}

	s.logger.WithFields(logrus.Fields{
		"tenant_id": tenantID,
		"user_id":   user.ID,
		"username":  user.Username,
		"email":     user.Email,
	}).Info("user updated successfully")

	return user, nil
}

func (s *userServiceImpl) Delete(ctx context.Context, tenantID, userID uuid.UUID) error {
	// Check if user exists
	if _, err := s.repos.User.GetByID(ctx, tenantID, userID); err != nil {
		return err
	}

	if err := s.repos.User.Delete(ctx, tenantID, userID); err != nil {
		s.logger.WithError(err).WithFields(logrus.Fields{
			"tenant_id": tenantID,
			"user_id":   userID,
		}).Error("failed to delete user")
		return fmt.Errorf("failed to delete user: %w", err)
	}
	if err := s.endSessions(ctx, tenantID, userID); err != nil {
		return err
	}

	s.logger.WithFields(logrus.Fields{
		"tenant_id": tenantID,
		"user_id":   userID,
	}).Info("user deleted successfully")

	return nil
}

func (s *userServiceImpl) List(ctx context.Context, tenantID uuid.UUID, limit, offset int) (*models.PaginatedResponse, error) {
	// Validate pagination parameters
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	if offset < 0 {
		offset = 0
	}

	users, total, err := s.repos.User.List(ctx, tenantID, limit, offset)
	if err != nil {
		s.logger.WithError(err).WithField("tenant_id", tenantID).Error("failed to list users")
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	return models.NewPaginatedResponse(
		models.UsersToInterface(users),
		limit,
		offset,
		total,
	), nil
}

func (s *userServiceImpl) Authenticate(ctx context.Context, tenantID uuid.UUID, email, password string) (*models.User, error) {
	// Get user by email
	user, err := s.repos.User.GetByEmail(ctx, tenantID, email)
	if err != nil {
		s.logger.WithFields(logrus.Fields{
			"tenant_id": tenantID,
			"email":     email,
		}).Warn("authentication failed - user not found")
		return nil, models.ErrInvalidCredentials
	}

	// Enforce lockout
	if user.IsLocked() {
		return nil, models.ErrUserLocked
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		_ = s.RecordLoginAttempt(ctx, tenantID, email, "", false)

		s.logger.WithFields(logrus.Fields{
			"tenant_id": tenantID,
			"user_id":   user.ID,
			"email":     email,
		}).Warn("authentication failed - invalid password")
		return nil, models.ErrInvalidCredentials
	}

	_ = s.RecordLoginAttempt(ctx, tenantID, email, "", true)

	s.logger.WithFields(logrus.Fields{
		"tenant_id": tenantID,
		"user_id":   user.ID,
		"email":     email,
	}).Info("user authenticated successfully")

	return user, nil
}

func (s *userServiceImpl) UpdateStatus(ctx context.Context, tenantID, userID uuid.UUID, status models.UserStatus) error {
	user, err := s.repos.User.GetByID(ctx, tenantID, userID)
	if err != nil {
		return err
	}
	user.Status = status
	user.UpdatedAt = time.Now()
	if err := s.repos.User.Update(ctx, user); err != nil {
		return err
	}
	if status == models.UserStatusSuspended || status == models.UserStatusLocked {
		return s.endSessions(ctx, tenantID, userID)
	}
	return nil
}

func (s *userServiceImpl) LockUser(ctx context.Context, tenantID, userID uuid.UUID, reason string, lockedUntil *time.Time) error {
	user, err := s.repos.User.GetByID(ctx, tenantID, userID)
	if err != nil {
		return err
	}
	now := time.Now()
	user.Status = models.UserStatusLocked
	user.LockedAt = &now
	user.LockedUntil = lockedUntil
	user.UpdatedAt = now
	_ = reason // reserved for audit/eventing; do not persist in user model for now
	if err := s.repos.User.Update(ctx, user); err != nil {
		return err
	}
	return s.endSessions(ctx, tenantID, userID)
}

func (s *userServiceImpl) UnlockUser(ctx context.Context, tenantID, userID uuid.UUID) error {
	user, err := s.repos.User.GetByID(ctx, tenantID, userID)
	if err != nil {
		return err
	}
	now := time.Now()
	user.Status = models.UserStatusActive
	user.FailedLoginAttempts = 0
	user.LockedAt = nil
	user.LockedUntil = nil
	user.UpdatedAt = now
	return s.repos.User.Update(ctx, user)
}

func (s *userServiceImpl) SuspendUser(ctx context.Context, tenantID, userID uuid.UUID, reason string) error {
	_ = reason
	return s.UpdateStatus(ctx, tenantID, userID, models.UserStatusSuspended)
}

func (s *userServiceImpl) ActivateUser(ctx context.Context, tenantID, userID uuid.UUID) error {
	return s.UpdateStatus(ctx, tenantID, userID, models.UserStatusActive)
}

// SendVerificationEmail emails the user a link proving they own their
// address. Earlier unused links stop working.
func (s *userServiceImpl) SendVerificationEmail(ctx context.Context, tenantID, userID uuid.UUID) error {
	if s.emails == nil || s.repos.EmailVerification == nil {
		return errAccountEmailsUnavailable
	}

	user, err := s.repos.User.GetByID(ctx, tenantID, userID)
	if err != nil {
		return err
	}
	if user.EmailVerified {
		return models.ErrEmailAlreadyVerified
	}

	code, err := randomToken(emailLinkTokenBytes)
	if err != nil {
		return fmt.Errorf("failed to generate verification code: %w", err)
	}
	if err := s.repos.EmailVerification.DeletePendingByUserID(ctx, tenantID, userID); err != nil {
		return err
	}
	if err := s.repos.EmailVerification.Create(ctx, &models.EmailVerification{
		ID:        uuid.New(),
		TenantID:  tenantID,
		UserID:    userID,
		Email:     user.Email,
		CodeHash:  hashToken(code),
		ExpiresAt: time.Now().Add(EmailVerificationDuration),
	}); err != nil {
		return err
	}

	link := s.baseURL + "/account/verify-email?code=" + url.QueryEscape(code)
	if err := s.emails.SendTemplateEmail(ctx, tenantID, user.Email, user.GetFullName(),
		string(models.EmailTemplateEmailVerification), map[string]string{
			"user_name":         displayName(user),
			"verification_link": link,
			"expires_hours":     strconv.Itoa(int(EmailVerificationDuration.Hours())),
		}, 1); err != nil {
		return fmt.Errorf("failed to send verification email: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"tenant_id": tenantID,
		"user_id":   userID,
	}).Info("verification email sent")
	return nil
}

// VerifyEmail consumes a verification code and marks the address verified.
// A pending account becomes active.
func (s *userServiceImpl) VerifyEmail(ctx context.Context, tenantID uuid.UUID, code string) (*models.User, error) {
	if s.repos.EmailVerification == nil {
		return nil, errAccountEmailsUnavailable
	}
	if code == "" {
		return nil, models.ErrInvalidVerificationCode
	}

	verification, err := s.repos.EmailVerification.GetByCodeHash(ctx, tenantID, hashToken(code))
	if err != nil {
		return nil, err
	}
	if verification.VerifiedAt != nil {
		return nil, models.ErrInvalidVerificationCode
	}
	if verification.IsExpired() {
		return nil, models.ErrVerificationExpired
	}

	user, err := s.repos.User.GetByID(ctx, tenantID, verification.UserID)
	if err != nil {
		return nil, err
	}
	// The link proves ownership of the address it was sent to, not of an
	// address the user switched to afterwards
	if !strings.EqualFold(user.Email, verification.Email) {
		return nil, models.ErrInvalidVerificationCode
	}

	claimed, err := s.repos.EmailVerification.MarkVerified(ctx, verification.ID)
	if err != nil {
		return nil, err
	}
	if !claimed {
		return nil, models.ErrInvalidVerificationCode
	}

	user.EmailVerified = true
	if user.Status == models.UserStatusPending {
		user.Status = models.UserStatusActive
	}
	user.UpdatedAt = time.Now()
	if err := s.repos.User.Update(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"tenant_id": tenantID,
		"user_id":   user.ID,
	}).Info("email verified")
	return user, nil
}

// RequestPasswordReset emails a single-use reset link. It returns nil for
// unknown or suspended accounts so callers cannot probe which emails exist.
func (s *userServiceImpl) RequestPasswordReset(ctx context.Context, tenantID uuid.UUID, email string) error {
	if s.emails == nil || s.repos.PasswordReset == nil {
		return errAccountEmailsUnavailable
	}

	user, err := s.repos.User.GetByEmail(ctx, tenantID, email)
	if errors.Is(err, models.ErrUserNotFound) {
		s.logger.WithField("tenant_id", tenantID).Info("password reset requested for unknown email")
		return nil
	}
	if err != nil {
		return err
	}
	logger := s.logger.WithFields(logrus.Fields{"tenant_id": tenantID, "user_id": user.ID})
	if user.IsSuspended() {
		logger.Warn("password reset requested for suspended user")
		return nil
	}

	recent, err := s.repos.PasswordReset.CountSince(ctx, tenantID, user.ID, time.Now().Add(-time.Hour))
	if err != nil {
		return err
	}
	if recent >= MaxPasswordResetsPerHour {
		logger.Warn("password reset rate limit reached")
		return nil
	}

	token, err := randomToken(emailLinkTokenBytes)
	if err != nil {
		return fmt.Errorf("failed to generate reset token: %w", err)
	}
	// Only the newest link works
	if err := s.repos.PasswordReset.RevokeUnusedByUserID(ctx, tenantID, user.ID); err != nil {
		return err
	}
	if err := s.repos.PasswordReset.Create(ctx, &models.PasswordReset{
		ID:        uuid.New(),
		TenantID:  tenantID,
		UserID:    user.ID,
		TokenHash: hashToken(token),
		ExpiresAt: time.Now().Add(PasswordResetDuration),
	}); err != nil {
		return err
	}

	link := s.baseURL + "/account/reset-password?token=" + url.QueryEscape(token)
	if err := s.emails.SendTemplateEmail(ctx, tenantID, user.Email, user.GetFullName(),
		string(models.EmailTemplatePasswordReset), map[string]string{
			"user_name":       displayName(user),
			"reset_link":      link,
			"expires_minutes": strconv.Itoa(int(PasswordResetDuration.Minutes())),
		}, 1); err != nil {
		return fmt.Errorf("failed to send password reset email: %w", err)
	}

	logger.Info("password reset email sent")
	return nil
}

// ResetPassword consumes a reset token and sets a new password. Because a
// reset usually means the old password is lost or compromised, it also ends
// every session and revokes every token issued to the user, and lifts a
// lockout caused by failed logins.
func (s *userServiceImpl) ResetPassword(ctx context.Context, tenantID uuid.UUID, token, newPassword string) (*models.User, error) {
	if s.repos.PasswordReset == nil {
		return nil, errAccountEmailsUnavailable
	}
	if len(newPassword) < MinPasswordLength {
		return nil, ErrPasswordTooShort
	}
	if token == "" {
		return nil, models.ErrInvalidVerificationCode
	}

	reset, err := s.repos.PasswordReset.GetByTokenHash(ctx, tenantID, hashToken(token))
	if err != nil {
		return nil, err
	}
	if reset.IsUsed() {
		return nil, models.ErrInvalidVerificationCode
	}
	if reset.IsExpired() {
		return nil, models.ErrVerificationExpired
	}

	user, err := s.repos.User.GetByID(ctx, tenantID, reset.UserID)
	if err != nil {
		return nil, err
	}
	if user.IsSuspended() {
		return nil, models.ErrUserSuspended
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	claimed, err := s.repos.PasswordReset.MarkUsed(ctx, reset.ID)
	if err != nil {
		return nil, err
	}
	if !claimed {
		return nil, models.ErrInvalidVerificationCode
	}

	now := time.Now()
	user.PasswordHash = string(hashedPassword)
	user.FailedLoginAttempts = 0
	// Lift a failed-login lockout (it has an end time); an administrator's
	// lock has none and stays
	if user.Status == models.UserStatusLocked && user.LockedUntil != nil {
		user.Status = models.UserStatusActive
		user.LockedAt = nil
		user.LockedUntil = nil
	}
	user.UpdatedAt = now
	if err := s.repos.User.Update(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to update user password: %w", err)
	}

	if err := s.revokeUserCredentials(ctx, tenantID, user.ID); err != nil {
		return nil, err
	}
	if err := s.repos.PasswordReset.RevokeUnusedByUserID(ctx, tenantID, user.ID); err != nil {
		s.logger.WithError(err).Error("failed to revoke other password reset tokens")
	}
	s.notifyPasswordChanged(ctx, user)

	s.logger.WithFields(logrus.Fields{
		"tenant_id": tenantID,
		"user_id":   user.ID,
	}).Info("password reset")
	return user, nil
}

func (s *userServiceImpl) RecordLoginAttempt(ctx context.Context, tenantID uuid.UUID, email, ipAddress string, success bool) error {
	user, err := s.repos.User.GetByEmail(ctx, tenantID, email)
	if err != nil {
		return nil
	}

	now := time.Now()

	if success {
		user.FailedLoginAttempts = 0
		user.LastLoginAt = &now
		user.LastLoginIP = ipAddress
		user.LockedAt = nil
		user.LockedUntil = nil
		if user.Status == models.UserStatusLocked {
			user.Status = models.UserStatusActive
		}
		user.UpdatedAt = now
		return s.repos.User.Update(ctx, user)
	}

	user.FailedLoginAttempts++
	user.UpdatedAt = now

	// Lockout after failed attempts deliberately keeps existing SSO sessions:
	// otherwise anyone who knows a user's email could sign them out
	if user.FailedLoginAttempts >= MaxLoginAttempts {
		lockedUntil := now.Add(LockoutDuration)
		user.Status = models.UserStatusLocked
		user.LockedAt = &now
		user.LockedUntil = &lockedUntil
	}

	return s.repos.User.Update(ctx, user)
}

func (s *userServiceImpl) GetLoginHistory(ctx context.Context, tenantID, userID uuid.UUID, limit, offset int) (*models.PaginatedResponse, error) {
	_ = ctx
	_ = tenantID
	_ = userID
	_ = limit
	_ = offset
	return models.NewPaginatedResponse([]interface{}{}, limit, offset, 0), nil
}

func (s *userServiceImpl) ChangePassword(ctx context.Context, tenantID, userID uuid.UUID, oldPassword, newPassword string) error {
	// Get user
	user, err := s.repos.User.GetByID(ctx, tenantID, userID)
	if err != nil {
		return err
	}

	// Verify old password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(oldPassword)); err != nil {
		return models.ErrInvalidCredentials
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Update password
	user.PasswordHash = string(hashedPassword)
	if err := s.repos.User.Update(ctx, user); err != nil {
		s.logger.WithError(err).WithFields(logrus.Fields{
			"tenant_id": tenantID,
			"user_id":   userID,
		}).Error("failed to change password")
		return fmt.Errorf("failed to change password: %w", err)
	}
	if err := s.endSessions(ctx, tenantID, userID); err != nil {
		return err
	}
	s.notifyPasswordChanged(ctx, user)

	s.logger.WithFields(logrus.Fields{
		"tenant_id": tenantID,
		"user_id":   userID,
	}).Info("password changed successfully")

	return nil
}

// endSessions signs the user out of every SSO session, so a suspended,
// locked or deleted account, or a changed password, takes effect in the
// browser too
func (s *userServiceImpl) endSessions(ctx context.Context, tenantID, userID uuid.UUID) error {
	if s.repos.Session == nil {
		return nil
	}
	if err := s.repos.Session.DeleteByUserID(ctx, tenantID, userID); err != nil {
		s.logger.WithError(err).WithFields(logrus.Fields{
			"tenant_id": tenantID,
			"user_id":   userID,
		}).Error("failed to end user sessions")
		return fmt.Errorf("failed to end user sessions: %w", err)
	}
	return nil
}

// revokeUserCredentials ends the user's sessions and revokes their access and
// refresh tokens
func (s *userServiceImpl) revokeUserCredentials(ctx context.Context, tenantID, userID uuid.UUID) error {
	if err := s.endSessions(ctx, tenantID, userID); err != nil {
		return err
	}
	if s.repos.AccessToken != nil {
		if err := s.repos.AccessToken.DeleteByUserID(ctx, tenantID, userID); err != nil {
			return fmt.Errorf("failed to revoke access tokens: %w", err)
		}
	}
	if s.repos.RefreshToken != nil {
		if err := s.repos.RefreshToken.DeleteByUserID(ctx, tenantID, userID); err != nil {
			return fmt.Errorf("failed to revoke refresh tokens: %w", err)
		}
	}
	return nil
}

// notifyPasswordChanged tells the user their password changed, so an
// unexpected change is noticed. Failure is logged, not returned: the
// password has already changed.
func (s *userServiceImpl) notifyPasswordChanged(ctx context.Context, user *models.User) {
	if s.emails == nil {
		return
	}
	if err := s.emails.SendTemplateEmail(ctx, user.TenantID, user.Email, user.GetFullName(),
		string(models.EmailTemplatePasswordChanged), map[string]string{"user_name": displayName(user)}, 1); err != nil {
		s.logger.WithError(err).WithFields(logrus.Fields{
			"tenant_id": user.TenantID,
			"user_id":   user.ID,
		}).Error("failed to send password changed email")
	}
}

// displayName is how emails greet the user
func displayName(user *models.User) string {
	if name := user.GetFullName(); name != "" {
		return name
	}
	if user.Username != "" {
		return user.Username
	}
	return user.Email
}
