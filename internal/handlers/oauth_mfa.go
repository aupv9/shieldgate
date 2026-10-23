package handlers

import (
	"context"
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"shieldgate/internal/middleware"
	"shieldgate/internal/models"
	"shieldgate/internal/observability"
	"shieldgate/internal/services"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// Flows that can ask for a second factor. The purpose is signed into the
// pending token so a token from one flow cannot complete the other.
const (
	mfaPurposeLogin  = "login"
	mfaPurposeDevice = "device"
)

// mfaPendingTTL bounds the time between the password and the second factor
const mfaPendingTTL = 5 * time.Minute

// errMFAPendingInvalid means the pending token is missing, forged, expired
// or meant for another tenant or flow
var errMFAPendingInvalid = errors.New("invalid MFA pending token")

// mfaPending is what the signed token between the password step and the
// second-factor step attests: this user passed the password check
type mfaPending struct {
	TenantID string `json:"t"`
	UserID   string `json:"u"`
	Purpose  string `json:"p"`
	Expires  int64  `json:"e"`
}

func newMFAPendingToken(secret string, p mfaPending) (string, error) {
	raw, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(raw)
	return payload + "." + signCSRFValue(secret, "mfa-pending:"+payload), nil
}

func parseMFAPendingToken(secret, token string, tenantID uuid.UUID, purpose string) (uuid.UUID, error) {
	payload, sig, found := strings.Cut(token, ".")
	if !found || !hmac.Equal([]byte(sig), []byte(signCSRFValue(secret, "mfa-pending:"+payload))) {
		return uuid.Nil, errMFAPendingInvalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return uuid.Nil, errMFAPendingInvalid
	}
	var p mfaPending
	if err := json.Unmarshal(raw, &p); err != nil {
		return uuid.Nil, errMFAPendingInvalid
	}
	if p.TenantID != tenantID.String() || p.Purpose != purpose || time.Now().Unix() > p.Expires {
		return uuid.Nil, errMFAPendingInvalid
	}
	userID, err := uuid.Parse(p.UserID)
	if err != nil {
		return uuid.Nil, errMFAPendingInvalid
	}
	return userID, nil
}

// mfaRequired reports whether the user must pass a second factor
func (h *OAuthHandler) mfaRequired(ctx context.Context, tenantID, userID uuid.UUID) (bool, error) {
	if h.mfaService == nil {
		return false, nil
	}
	return h.mfaService.IsEnabled(ctx, tenantID, userID)
}

// startMFA shows the second-factor form after a correct password. hidden
// carries the flow's own fields (the authorization request, or the device
// code and decision) through the form.
func (h *OAuthHandler) startMFA(c *gin.Context, tenantID, userID uuid.UUID, purpose, action string, hidden gin.H) {
	token, err := newMFAPendingToken(h.cfg.JWTSecret, mfaPending{
		TenantID: tenantID.String(),
		UserID:   userID.String(),
		Purpose:  purpose,
		Expires:  time.Now().Add(mfaPendingTTL).Unix(),
	})
	if err != nil {
		h.logger.WithError(err).Error("failed to create MFA pending token")
		h.renderError(c, "server_error", "Internal server error", "", "")
		return
	}
	h.renderMFAPage(c, action, hidden, token, "")
}

func (h *OAuthHandler) renderMFAPage(c *gin.Context, action string, hidden gin.H, pendingToken, errorMsg string) {
	data := gin.H{"action": action, "hidden": hidden, "mfa_token": pendingToken}
	if !h.addCSRFToken(c, data) {
		return
	}
	if errorMsg != "" {
		data["error"] = errorMsg
	}
	c.HTML(http.StatusOK, "mfa.html", data)
}

// completeMFA checks the submitted second factor. On a wrong code it shows
// the form again; when the flow cannot continue (expired, locked) it calls
// restart. On success it returns the user and the amr values to record.
func (h *OAuthHandler) completeMFA(c *gin.Context, tenantID uuid.UUID, purpose, action string, hidden gin.H, restart func(msg string)) (uuid.UUID, []string, bool) {
	pendingToken := c.PostForm("mfa_token")
	userID, err := parseMFAPendingToken(h.cfg.JWTSecret, pendingToken, tenantID, purpose)
	if err != nil {
		restart("Your sign-in took too long — please enter your password again")
		return uuid.Nil, nil, false
	}
	logger := h.logger.WithFields(logrus.Fields{"tenant_id": tenantID, "user_id": userID, "flow": purpose})

	// The account may have been suspended or locked since the password step
	user, err := h.userService.GetByID(c.Request.Context(), tenantID, userID)
	if err != nil || user.IsSuspended() || user.IsLocked() {
		logger.Warn("second factor submitted for unavailable account")
		restart("Invalid email or password")
		return uuid.Nil, nil, false
	}

	method, err := h.mfaService.Verify(c.Request.Context(), tenantID, userID, c.PostForm("code"))
	switch {
	case err == nil:
		logger.WithField("method", method).Info("second factor verified")
		h.record(c, observability.Event{Name: "mfa", Result: "success"})
		return userID, services.AMRForSecondFactor(method), true
	case errors.Is(err, models.ErrInvalidMFACode):
		h.recordMFAFailure(c, tenantID, userID, purpose, "invalid_code")
		h.renderMFAPage(c, action, hidden, pendingToken, "Invalid code — please try again")
	case errors.Is(err, models.ErrMFALocked):
		logger.Warn("second factor locked after repeated failures")
		h.recordMFAFailure(c, tenantID, userID, purpose, "locked")
		restart("Too many incorrect codes — please try again in 15 minutes")
	case errors.Is(err, models.ErrMFANotEnabled):
		// Disabled since the password step: start over
		restart("Please sign in again")
	default:
		logger.WithError(err).Error("second factor verification failed")
		restart("Something went wrong — please try again")
	}
	return uuid.Nil, nil, false
}

// recordMFAFailure audits a rejected second factor
func (h *OAuthHandler) recordMFAFailure(c *gin.Context, tenantID, userID uuid.UUID, flow, result string) {
	h.record(c, observability.Event{
		Action: models.AuditActionMFAFailed, TenantID: tenantID, UserID: &userID, ErrorCode: result,
		Metadata: map[string]interface{}{"flow": flow}, Name: "mfa", Result: result,
	})
}

// HandleLoginMFA handles POST /oauth/login/mfa: the second factor of a
// browser login
func (h *OAuthHandler) HandleLoginMFA(c *gin.Context) {
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		h.renderError(c, "invalid_request", "Tenant context required — use the tenant's domain or provide X-Tenant-ID", "", "")
		return
	}
	if !h.validCSRF(c) {
		h.logger.WithField("tenant_id", tenantID).Warn("CSRF validation failed on MFA endpoint")
		h.renderError(c, "invalid_request", "Invalid or missing CSRF token — please retry the authorization flow", "", "")
		return
	}

	ar, ok := h.validateAuthorizationRequest(c, tenantID, readAuthorizeRequest(c.PostForm))
	if !ok {
		return
	}

	restart := func(msg string) { h.renderLoginPage(c, tenantID, ar, msg) }
	userID, amr, ok := h.completeMFA(c, tenantID, mfaPurposeLogin, "/oauth/login/mfa", authorizationFormData(ar), restart)
	if !ok {
		return
	}
	h.signIn(c, tenantID, ar, userID, amr)
}

// HandleDeviceMFA handles POST /oauth/device/mfa: the second factor of a
// device approval
func (h *OAuthHandler) HandleDeviceMFA(c *gin.Context) {
	tenantID, err := middleware.GetTenantID(c)
	if err != nil {
		h.renderError(c, "invalid_request", "Tenant context required — provide X-Tenant-ID header", "", "")
		return
	}
	tenant, _ := h.tenantService.GetByID(c.Request.Context(), tenantID)
	userCode, action := c.PostForm("user_code"), c.PostForm("action")

	if !h.validCSRF(c) {
		h.renderDevicePage(c, tenant, userCode, "Invalid or missing CSRF token — please reload the page", "")
		return
	}

	restart := func(msg string) { h.renderDevicePage(c, tenant, userCode, msg, "") }
	hidden := gin.H{"user_code": userCode, "action": action}
	userID, amr, ok := h.completeMFA(c, tenantID, mfaPurposeDevice, "/oauth/device/mfa", hidden, restart)
	if !ok {
		return
	}
	h.applyDeviceDecision(c, tenant, tenantID, userID, userCode, action, amr)
}
