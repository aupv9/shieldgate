package services

import (
	"context"
	"fmt"
	"time"

	"shieldgate/internal/crypto"
	"shieldgate/internal/models"
	"shieldgate/internal/repo"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

const backupCodeCount = 8

type mfaServiceImpl struct {
	repos  *repo.Repositories
	logger *logrus.Logger
}

func NewMFAService(repos *repo.Repositories, logger *logrus.Logger) MFAService {
	return &mfaServiceImpl{repos: repos, logger: logger}
}

func (s *mfaServiceImpl) Setup(ctx context.Context, tenantID, userID uuid.UUID, issuer, accountName string) (*models.MFASetupResponse, error) {
	// Delete any pending (non-enabled) secret first
	existing, err := s.repos.MFASecret.GetByUserID(ctx, tenantID, userID)
	if err == nil && existing.Enabled {
		return nil, models.ErrMFAAlreadyEnabled
	}
	if err == nil {
		_ = s.repos.MFASecret.Delete(ctx, tenantID, userID)
	}

	secret, err := crypto.GenerateTOTPSecret()
	if err != nil {
		return nil, fmt.Errorf("failed to generate TOTP secret: %w", err)
	}

	mfaSecret := &models.MFASecret{
		ID:        uuid.New(),
		TenantID:  tenantID,
		UserID:    userID,
		Secret:    secret,
		Algorithm: "SHA1",
		Digits:    crypto.DefaultTOTPDigits,
		Period:    crypto.DefaultTOTPPeriod,
		Enabled:   false,
	}
	if err := s.repos.MFASecret.Create(ctx, mfaSecret); err != nil {
		return nil, fmt.Errorf("failed to store MFA secret: %w", err)
	}

	provURI := crypto.TOTPProvisioningURI(issuer, accountName, secret,
		crypto.DefaultTOTPPeriod, crypto.DefaultTOTPDigits)

	return &models.MFASetupResponse{
		Secret:          secret,
		ProvisioningURI: provURI,
		QRCodeHint:      "Scan the provisioning_uri with an authenticator app such as Google Authenticator or Authy.",
	}, nil
}

func (s *mfaServiceImpl) VerifyAndEnable(ctx context.Context, tenantID, userID uuid.UUID, code string) error {
	mfaSecret, err := s.repos.MFASecret.GetByUserID(ctx, tenantID, userID)
	if err != nil {
		return models.ErrMFANotSetup
	}
	if mfaSecret.Enabled {
		return models.ErrMFAAlreadyEnabled
	}
	if !crypto.ValidateTOTP(mfaSecret.Secret, code, mfaSecret.Period, mfaSecret.Digits) {
		return models.ErrMFAInvalidCode
	}

	mfaSecret.Enabled = true
	if err := s.repos.MFASecret.Update(ctx, mfaSecret); err != nil {
		return fmt.Errorf("failed to enable MFA: %w", err)
	}

	// Generate initial backup codes
	if _, err := s.generateAndStoreBackupCodes(ctx, tenantID, userID); err != nil {
		s.logger.WithError(err).Warn("failed to generate backup codes after MFA enable")
	}
	return nil
}

func (s *mfaServiceImpl) Disable(ctx context.Context, tenantID, userID uuid.UUID, code string) error {
	mfaSecret, err := s.repos.MFASecret.GetByUserID(ctx, tenantID, userID)
	if err != nil {
		return models.ErrMFANotSetup
	}
	if !mfaSecret.Enabled {
		return models.ErrMFANotEnabled
	}

	// Accept either TOTP code or a backup code
	valid := crypto.ValidateTOTP(mfaSecret.Secret, code, mfaSecret.Period, mfaSecret.Digits)
	if !valid {
		ok, _ := s.useBackupCode(ctx, tenantID, userID, code)
		if !ok {
			return models.ErrMFAInvalidCode
		}
	}

	_ = s.repos.MFABackupCode.DeleteByUserID(ctx, tenantID, userID)
	return s.repos.MFASecret.Delete(ctx, tenantID, userID)
}

func (s *mfaServiceImpl) ValidateCode(ctx context.Context, tenantID, userID uuid.UUID, code string) (bool, error) {
	mfaSecret, err := s.repos.MFASecret.GetByUserID(ctx, tenantID, userID)
	if err != nil {
		return false, models.ErrMFANotSetup
	}
	if !mfaSecret.Enabled {
		return false, models.ErrMFANotEnabled
	}
	if crypto.ValidateTOTP(mfaSecret.Secret, code, mfaSecret.Period, mfaSecret.Digits) {
		return true, nil
	}
	// Try backup code
	ok, err := s.useBackupCode(ctx, tenantID, userID, code)
	return ok, err
}

func (s *mfaServiceImpl) IsEnabled(ctx context.Context, tenantID, userID uuid.UUID) (bool, error) {
	secret, err := s.repos.MFASecret.GetByUserID(ctx, tenantID, userID)
	if err != nil {
		return false, nil
	}
	return secret.Enabled, nil
}

func (s *mfaServiceImpl) GetBackupCodes(ctx context.Context, tenantID, userID uuid.UUID) ([]*models.MFABackupCode, error) {
	return s.repos.MFABackupCode.GetByUserID(ctx, tenantID, userID)
}

func (s *mfaServiceImpl) RegenerateBackupCodes(ctx context.Context, tenantID, userID uuid.UUID) ([]string, error) {
	if err := s.repos.MFABackupCode.DeleteByUserID(ctx, tenantID, userID); err != nil {
		return nil, fmt.Errorf("failed to delete old backup codes: %w", err)
	}
	return s.generateAndStoreBackupCodes(ctx, tenantID, userID)
}

// generateAndStoreBackupCodes creates new codes, stores hashed versions, returns plain-text.
func (s *mfaServiceImpl) generateAndStoreBackupCodes(ctx context.Context, tenantID, userID uuid.UUID) ([]string, error) {
	plainCodes, err := crypto.GenerateBackupCodes(backupCodeCount)
	if err != nil {
		return nil, err
	}
	records := make([]*models.MFABackupCode, len(plainCodes))
	for i, c := range plainCodes {
		hash, err := bcrypt.GenerateFromPassword([]byte(c), bcrypt.DefaultCost)
		if err != nil {
			return nil, fmt.Errorf("failed to hash backup code: %w", err)
		}
		records[i] = &models.MFABackupCode{
			ID:       uuid.New(),
			TenantID: tenantID,
			UserID:   userID,
			CodeHash: string(hash),
		}
	}
	if err := s.repos.MFABackupCode.CreateBatch(ctx, records); err != nil {
		return nil, fmt.Errorf("failed to store backup codes: %w", err)
	}
	return plainCodes, nil
}

// useBackupCode attempts to find and consume a matching backup code.
func (s *mfaServiceImpl) useBackupCode(ctx context.Context, tenantID, userID uuid.UUID, code string) (bool, error) {
	codes, err := s.repos.MFABackupCode.GetByUserID(ctx, tenantID, userID)
	if err != nil {
		return false, err
	}
	for _, bc := range codes {
		if bc.IsUsed() {
			continue
		}
		if bcrypt.CompareHashAndPassword([]byte(bc.CodeHash), []byte(code)) == nil {
			now := time.Now()
			_ = s.repos.MFABackupCode.MarkUsed(ctx, bc.ID)
			_ = now
			return true, nil
		}
	}
	return false, nil
}
