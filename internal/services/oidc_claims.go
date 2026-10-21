package services

import (
	"strings"
	"time"

	"shieldgate/internal/models"
)

// OIDC scopes that release user claims (OIDC Core §5.4)
const (
	ScopeOpenID  = "openid"
	ScopeProfile = "profile"
	ScopeEmail   = "email"
	ScopePhone   = "phone"
)

// authContext is what the user's original authentication established. It is
// stored with refresh tokens so ID tokens issued on refresh keep the original
// auth_time (OIDC Core §12.2).
type authContext struct {
	authTime *time.Time
	// nonce is echoed only in the ID token of the initial code exchange
	nonce string
}

// userClaimsForScope returns sub plus the user claims each granted scope
// releases (OIDC Core §5.4); claims of scopes not granted are left empty
func userClaimsForScope(user *models.User, scope string) models.UserInfo {
	claims := models.UserInfo{Sub: user.ID.String()}

	if ScopeContains(scope, ScopeProfile) {
		claims.Name = strings.TrimSpace(user.FirstName + " " + user.LastName)
		if claims.Name == "" {
			claims.Name = user.Username
		}
		claims.GivenName = user.FirstName
		claims.FamilyName = user.LastName
		claims.PreferredUsername = user.Username
		claims.Picture = user.Avatar
		claims.Locale = user.Locale
		claims.Zoneinfo = user.Timezone
		if !user.UpdatedAt.IsZero() {
			claims.UpdatedAt = user.UpdatedAt.Unix()
		}
	}

	if ScopeContains(scope, ScopeEmail) {
		verified := user.EmailVerified
		claims.Email = user.Email
		claims.EmailVerified = &verified
	}

	if ScopeContains(scope, ScopePhone) && user.PhoneNumber != "" {
		verified := user.PhoneVerified
		claims.PhoneNumber = user.PhoneNumber
		claims.PhoneNumberVerified = &verified
	}

	return claims
}
