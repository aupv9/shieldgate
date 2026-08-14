package tests

// oauth_device_handler_test.go covers the HTTP layer of the device
// authorization grant (RFC 8628) and token exchange (RFC 8693).

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"shieldgate/internal/models"
)

const (
	grantTypeDeviceCode    = "urn:ietf:params:oauth:grant-type:device_code"
	grantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
)

// ---- Device authorization endpoint ----

func TestHandleDeviceAuthorization_NoClientAuth_Returns401(t *testing.T) {
	f := newHandlerFixture()

	w := f.postForm("/oauth/device_authorization", url.Values{})

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	f.authService.AssertNotCalled(t, "CreateDeviceAuthorization", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestHandleDeviceAuthorization_GrantNotRegistered_Rejected(t *testing.T) {
	f := newHandlerFixture()
	client := confidentialClient(f.tenantID, []string{"authorization_code"}, []string{"read"})
	f.clientService.On("ValidateClient", mock.Anything, f.tenantID, "conf-client", "s3cret").Return(client, nil)

	w := f.postForm("/oauth/device_authorization", url.Values{}, "conf-client", "s3cret")

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "unauthorized_client")
}

func TestHandleDeviceAuthorization_Success(t *testing.T) {
	f := newHandlerFixture()
	client := confidentialClient(f.tenantID, []string{grantTypeDeviceCode}, []string{"read"})
	f.clientService.On("ValidateClient", mock.Anything, f.tenantID, "conf-client", "s3cret").Return(client, nil)
	f.authService.On("CreateDeviceAuthorization", mock.Anything, f.tenantID, client, "read").
		Return(&models.DeviceAuthorizationResponse{
			DeviceCode:              "dev-code",
			UserCode:                "BCDF-GHJK",
			VerificationURI:         "http://localhost:8080/oauth/device",
			VerificationURIComplete: "http://localhost:8080/oauth/device?user_code=BCDF-GHJK",
			ExpiresIn:               600,
			Interval:                5,
		}, nil)

	form := url.Values{}
	form.Set("scope", "read")
	w := f.postForm("/oauth/device_authorization", form, "conf-client", "s3cret")

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "BCDF-GHJK")
	assert.Contains(t, w.Body.String(), "device_code")
	f.authService.AssertExpectations(t)
}

func TestHandleDeviceAuthorization_ScopeOutsideRegistration_Rejected(t *testing.T) {
	f := newHandlerFixture()
	client := confidentialClient(f.tenantID, []string{grantTypeDeviceCode}, []string{"read"})
	f.clientService.On("ValidateClient", mock.Anything, f.tenantID, "conf-client", "s3cret").Return(client, nil)

	form := url.Values{}
	form.Set("scope", "read admin")
	w := f.postForm("/oauth/device_authorization", form, "conf-client", "s3cret")

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid_scope")
}

// ---- Token endpoint: device_code grant ----

func TestHandleToken_DeviceCodeGrant_PendingErrorMapped(t *testing.T) {
	f := newHandlerFixture()
	client := confidentialClient(f.tenantID, []string{grantTypeDeviceCode}, []string{"read"})
	f.clientService.On("ValidateClient", mock.Anything, f.tenantID, "conf-client", "s3cret").Return(client, nil)
	f.authService.On("ExchangeDeviceCode", mock.Anything, f.tenantID, client, "dev-code").
		Return(nil, models.ErrAuthorizationPending)

	form := url.Values{}
	form.Set("grant_type", grantTypeDeviceCode)
	form.Set("device_code", "dev-code")
	w := f.postForm("/oauth/token", form, "conf-client", "s3cret")

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "authorization_pending")
}

func TestHandleToken_DeviceCodeGrant_SlowDownMapped(t *testing.T) {
	f := newHandlerFixture()
	client := confidentialClient(f.tenantID, []string{grantTypeDeviceCode}, []string{"read"})
	f.clientService.On("ValidateClient", mock.Anything, f.tenantID, "conf-client", "s3cret").Return(client, nil)
	f.authService.On("ExchangeDeviceCode", mock.Anything, f.tenantID, client, "dev-code").
		Return(nil, models.ErrSlowDown)

	form := url.Values{}
	form.Set("grant_type", grantTypeDeviceCode)
	form.Set("device_code", "dev-code")
	w := f.postForm("/oauth/token", form, "conf-client", "s3cret")

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "slow_down")
}

func TestHandleToken_DeviceCodeGrant_Success(t *testing.T) {
	f := newHandlerFixture()
	client := confidentialClient(f.tenantID, []string{grantTypeDeviceCode}, []string{"read"})
	f.clientService.On("ValidateClient", mock.Anything, f.tenantID, "conf-client", "s3cret").Return(client, nil)
	f.authService.On("ExchangeDeviceCode", mock.Anything, f.tenantID, client, "dev-code").
		Return(&models.TokenResponse{AccessToken: "at", TokenType: "Bearer", ExpiresIn: 3600, RefreshToken: "rt", Scope: "read"}, nil)

	form := url.Values{}
	form.Set("grant_type", grantTypeDeviceCode)
	form.Set("device_code", "dev-code")
	w := f.postForm("/oauth/token", form, "conf-client", "s3cret")

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "access_token")
	f.authService.AssertExpectations(t)
}

func TestHandleToken_DeviceCodeGrant_MissingDeviceCode_Rejected(t *testing.T) {
	f := newHandlerFixture()

	form := url.Values{}
	form.Set("grant_type", grantTypeDeviceCode)
	w := f.postForm("/oauth/token", form, "conf-client", "s3cret")

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid_request")
}

// ---- Token endpoint: token exchange grant ----

func TestHandleToken_TokenExchange_PublicClientRejected(t *testing.T) {
	f := newHandlerFixture()
	publicClient := &models.Client{ID: uuid.New(), TenantID: f.tenantID, ClientID: "spa-client", IsPublic: true,
		GrantTypes: models.StringArray{grantTypeTokenExchange}}
	f.clientService.On("ValidateClient", mock.Anything, f.tenantID, "spa-client", "").Return(publicClient, nil)

	form := url.Values{}
	form.Set("grant_type", grantTypeTokenExchange)
	form.Set("client_id", "spa-client")
	form.Set("subject_token", "subject")
	form.Set("subject_token_type", models.TokenTypeAccessToken)
	w := f.postForm("/oauth/token", form)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	f.authService.AssertNotCalled(t, "ExchangeToken", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestHandleToken_TokenExchange_MissingSubjectToken_Rejected(t *testing.T) {
	f := newHandlerFixture()
	client := confidentialClient(f.tenantID, []string{grantTypeTokenExchange}, []string{"read"})
	f.clientService.On("ValidateClient", mock.Anything, f.tenantID, "conf-client", "s3cret").Return(client, nil)

	form := url.Values{}
	form.Set("grant_type", grantTypeTokenExchange)
	w := f.postForm("/oauth/token", form, "conf-client", "s3cret")

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid_request")
}

func TestHandleToken_TokenExchange_UnsupportedRequestedType_Rejected(t *testing.T) {
	f := newHandlerFixture()
	client := confidentialClient(f.tenantID, []string{grantTypeTokenExchange}, []string{"read"})
	f.clientService.On("ValidateClient", mock.Anything, f.tenantID, "conf-client", "s3cret").Return(client, nil)

	form := url.Values{}
	form.Set("grant_type", grantTypeTokenExchange)
	form.Set("subject_token", "subject")
	form.Set("subject_token_type", models.TokenTypeAccessToken)
	form.Set("requested_token_type", "urn:ietf:params:oauth:token-type:refresh_token")
	w := f.postForm("/oauth/token", form, "conf-client", "s3cret")

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid_request")
}

func TestHandleToken_TokenExchange_Success(t *testing.T) {
	f := newHandlerFixture()
	client := confidentialClient(f.tenantID, []string{grantTypeTokenExchange}, []string{"read"})
	f.clientService.On("ValidateClient", mock.Anything, f.tenantID, "conf-client", "s3cret").Return(client, nil)
	f.authService.On("ExchangeToken", mock.Anything, f.tenantID, client, "subject", models.TokenTypeAccessToken, "read").
		Return(&models.TokenExchangeResponse{
			AccessToken:     "exchanged",
			IssuedTokenType: models.TokenTypeAccessToken,
			TokenType:       "Bearer",
			ExpiresIn:       3600,
			Scope:           "read",
		}, nil)

	form := url.Values{}
	form.Set("grant_type", grantTypeTokenExchange)
	form.Set("subject_token", "subject")
	form.Set("subject_token_type", models.TokenTypeAccessToken)
	form.Set("scope", "read")
	w := f.postForm("/oauth/token", form, "conf-client", "s3cret")

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "exchanged")
	assert.Contains(t, w.Body.String(), "issued_token_type")
	f.authService.AssertExpectations(t)
}

func TestHandleToken_TokenExchange_GrantNotRegistered_Rejected(t *testing.T) {
	f := newHandlerFixture()
	client := confidentialClient(f.tenantID, []string{"authorization_code"}, []string{"read"})
	f.clientService.On("ValidateClient", mock.Anything, f.tenantID, "conf-client", "s3cret").Return(client, nil)

	form := url.Values{}
	form.Set("grant_type", grantTypeTokenExchange)
	form.Set("subject_token", "subject")
	form.Set("subject_token_type", models.TokenTypeAccessToken)
	w := f.postForm("/oauth/token", form, "conf-client", "s3cret")

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "unauthorized_client")
}
