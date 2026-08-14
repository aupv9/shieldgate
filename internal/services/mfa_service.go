package services

// mfa_service.go implements TOTP-based MFA management on userServiceImpl.
// The TOTP secret is stored on the user record; encrypt-at-rest is a
// deployment concern (database/KMS level).

import (
	"context"
	"time"

	"shieldgate/internal/models"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

const mfaIssuer = "ShieldGate"

func (s *userServiceImpl) EnrollMFA(ctx context.Context, tenantID, userID uuid.UUID) (string, string, error) {
	user, err := s.repos.User.GetByID(ctx, tenantID, userID)
	if err != nil {
		return "", "", err
	}
	if user.MFAEnabled {
		return "", "", models.ErrMFAAlreadyActive
	}

	secret, err := GenerateTOTPSecret()
	if err != nil {
		return "", "", err
	}

	user.MFASecret = secret
	if err := s.repos.User.Update(ctx, user); err != nil {
		return "", "", err
	}

	s.logger.WithFields(logrus.Fields{
		"tenant_id": tenantID,
		"user_id":   userID,
	}).Info("MFA enrollment started")

	return secret, BuildOTPAuthURI(mfaIssuer, user.Email, secret), nil
}

func (s *userServiceImpl) ActivateMFA(ctx context.Context, tenantID, userID uuid.UUID, code string) error {
	user, err := s.repos.User.GetByID(ctx, tenantID, userID)
	if err != nil {
		return err
	}
	if user.MFAEnabled {
		return models.ErrMFAAlreadyActive
	}
	if user.MFASecret == "" {
		return models.ErrMFANotEnrolled
	}
	if !ValidateTOTPCode(user.MFASecret, code, time.Now()) {
		return models.ErrMFAInvalidCode
	}

	user.MFAEnabled = true
	if err := s.repos.User.Update(ctx, user); err != nil {
		return err
	}

	s.logger.WithFields(logrus.Fields{
		"tenant_id": tenantID,
		"user_id":   userID,
	}).Info("MFA activated")
	return nil
}

func (s *userServiceImpl) DisableMFA(ctx context.Context, tenantID, userID uuid.UUID, code string) error {
	user, err := s.repos.User.GetByID(ctx, tenantID, userID)
	if err != nil {
		return err
	}
	if !user.MFAEnabled {
		return models.ErrMFANotEnrolled
	}
	// Disabling requires proving possession of the authenticator
	if !ValidateTOTPCode(user.MFASecret, code, time.Now()) {
		return models.ErrMFAInvalidCode
	}

	user.MFAEnabled = false
	user.MFASecret = ""
	if err := s.repos.User.Update(ctx, user); err != nil {
		return err
	}

	s.logger.WithFields(logrus.Fields{
		"tenant_id": tenantID,
		"user_id":   userID,
	}).Info("MFA disabled")
	return nil
}

func (s *userServiceImpl) VerifyMFA(ctx context.Context, tenantID, userID uuid.UUID, code string) error {
	user, err := s.repos.User.GetByID(ctx, tenantID, userID)
	if err != nil {
		return err
	}
	if !user.MFAEnabled || user.MFASecret == "" {
		return models.ErrMFANotEnrolled
	}
	if !ValidateTOTPCode(user.MFASecret, code, time.Now()) {
		return models.ErrMFAInvalidCode
	}
	return nil
}
