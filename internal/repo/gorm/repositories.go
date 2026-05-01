package gorm

import (
	"shieldgate/internal/repo"

	"gorm.io/gorm"
)

// NewRepositories creates all GORM repository implementations.
func NewRepositories(db *gorm.DB) *repo.Repositories {
	return &repo.Repositories{
		Tenant:         NewTenantRepository(db),
		User:           NewUserRepository(db),
		Client:         NewClientRepository(db),
		AuthCode:       NewAuthCodeRepository(db),
		AccessToken:    NewAccessTokenRepository(db),
		RefreshToken:   NewRefreshTokenRepository(db),
		MFASecret:      NewMFASecretRepository(db),
		MFABackupCode:  NewMFABackupCodeRepository(db),
		Session:        NewSessionRepository(db),
		LoginAttempt:   NewLoginAttemptRepository(db),
		// Phase 7
		SocialAccount:  NewSocialAccountRepository(db),
		SocialProvider: NewSocialProviderRepository(db),
		Webhook:        NewWebhookRepository(db),
		APIKey:         NewAPIKeyRepository(db),
		// Phase 16
		Consent:   NewConsentRepository(db),
		Blocklist: NewBlocklistRepository(db),
		// Phase 18
		DeviceCode: NewDeviceCodeRepository(db),
	}
}
