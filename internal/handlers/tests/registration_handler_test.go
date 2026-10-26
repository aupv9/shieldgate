package tests

// registration_handler_test.go covers roadmap 4.2 at the HTTP layer: the
// RFC 7591/7592 wire format, bearer handling and error responses.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"shieldgate/internal/handlers"
	"shieldgate/internal/middleware"
	"shieldgate/internal/models"
	"shieldgate/internal/observability"
)

// fakeRegistration accepts the bearer "good" and fails with err otherwise
type fakeRegistration struct {
	err       error
	gotToken  string
	gotMeta   *models.ClientMetadata
	gotClient string
}

func (f *fakeRegistration) result(token string) error {
	f.gotToken = token
	if f.err != nil {
		return f.err
	}
	if token != "good" {
		return models.ErrInvalidToken
	}
	return nil
}

func (f *fakeRegistration) response() *models.ClientRegistrationResponse {
	return &models.ClientRegistrationResponse{
		ClientMetadata: models.ClientMetadata{GrantTypes: []string{"authorization_code"}, TokenEndpointAuthMethod: "client_secret_basic"},
		ClientID:       "client_abc", ClientSecret: "s3cret", RegistrationAccessToken: "rat",
		RegistrationClientURI: "https://auth.example/oauth/register/client_abc",
	}
}

func (f *fakeRegistration) CreateInitialAccessToken(ctx context.Context, tenantID uuid.UUID, createdBy *uuid.UUID, req *models.CreateInitialAccessTokenRequest) (*models.CreatedInitialAccessToken, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &models.CreatedInitialAccessToken{
		InitialAccessToken: &models.InitialAccessToken{ID: uuid.New(), Scopes: models.StringArray(req.Scopes), MaxUses: 1, CreatedBy: createdBy},
		Token:              "iat-value",
	}, nil
}

func (f *fakeRegistration) ListInitialAccessTokens(ctx context.Context, tenantID uuid.UUID) ([]*models.InitialAccessToken, error) {
	return []*models.InitialAccessToken{}, nil
}

func (f *fakeRegistration) RevokeInitialAccessToken(ctx context.Context, tenantID, id uuid.UUID) error {
	return models.ErrInitialAccessTokenNotFound
}

func (f *fakeRegistration) Register(ctx context.Context, tenantID uuid.UUID, token string, meta *models.ClientMetadata) (*models.ClientRegistrationResponse, error) {
	f.gotMeta = meta
	if err := f.result(token); err != nil {
		return nil, err
	}
	return f.response(), nil
}

func (f *fakeRegistration) Read(ctx context.Context, tenantID uuid.UUID, clientID, token string) (*models.ClientRegistrationResponse, error) {
	f.gotClient = clientID
	if err := f.result(token); err != nil {
		return nil, err
	}
	resp := f.response()
	resp.ClientSecret, resp.RegistrationAccessToken = "", ""
	return resp, nil
}

func (f *fakeRegistration) Update(ctx context.Context, tenantID uuid.UUID, clientID, token string, meta *models.ClientMetadata) (*models.ClientRegistrationResponse, error) {
	f.gotClient, f.gotMeta = clientID, meta
	if err := f.result(token); err != nil {
		return nil, err
	}
	return f.response(), nil
}

func (f *fakeRegistration) Delete(ctx context.Context, tenantID uuid.UUID, clientID, token string) error {
	f.gotClient = clientID
	return f.result(token)
}

type registrationRouter struct {
	svc    *fakeRegistration
	audit  *fakeAuditLog
	router *gin.Engine
	admin  uuid.UUID
}

func newRegistrationRouter(t *testing.T) *registrationRouter {
	t.Helper()
	gin.SetMode(gin.TestMode)
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)
	r := &registrationRouter{svc: &fakeRegistration{}, audit: &fakeAuditLog{}, router: gin.New(), admin: uuid.New()}
	tenantID := uuid.New()
	r.router.Use(func(c *gin.Context) {
		c.Set(middleware.TenantIDKey, tenantID)
		if user := c.GetHeader("X-Test-User"); user != "" {
			c.Set(middleware.UserIDKey, uuid.MustParse(user))
		}
		c.Next()
	})
	h := handlers.NewRegistrationHandler(r.svc, logger).WithRecorder(observability.NewRecorder(r.audit, nil, logger))
	h.RegisterRoutes(r.router.Group(""))
	h.RegisterManagementRoutes(r.router.Group("/v1"), middleware.NewAuthorizer(denyAll{}, []uuid.UUID{r.admin}, logger))
	return r
}

func (r *registrationRouter) do(method, path, auth, body string, headers ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	w := httptest.NewRecorder()
	r.router.ServeHTTP(w, req)
	return w
}

func TestRegistrationEndpoint_Success_RFC7591Response(t *testing.T) {
	// Arrange
	r := newRegistrationRouter(t)
	body := `{"redirect_uris":["https://partner.example/cb"],"client_name":"Partner","logo_uri":"https://x/logo.png"}`

	// Act
	w := r.do(http.MethodPost, "/oauth/register", "bearer good", body)

	// Assert
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	assert.Equal(t, "no-cache", w.Header().Get("Pragma"))
	assert.Equal(t, "good", r.svc.gotToken, "the bearer scheme is case-insensitive")
	assert.Equal(t, "Partner", r.svc.gotMeta.ClientName)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "client_abc", resp["client_id"])
	assert.Equal(t, "s3cret", resp["client_secret"])
	assert.Equal(t, "rat", resp["registration_access_token"])
	assert.Equal(t, "https://auth.example/oauth/register/client_abc", resp["registration_client_uri"])
	assert.NotContains(t, resp, "data", "RFC 7591 responses are not wrapped")
	entry := r.audit.find(t, models.AuditActionClientCreated)
	assert.Equal(t, "dynamic", entry.Metadata["registration"])
	assert.NotContains(t, entry.Metadata, "client_secret")
}

func TestRegistrationEndpoint_Errors(t *testing.T) {
	tests := []struct {
		name       string
		auth       string
		body       string
		err        error
		wantStatus int
		wantError  string
	}{
		{"no token", "", `{}`, nil, http.StatusUnauthorized, "invalid_token"},
		{"wrong scheme", "Basic good", `{}`, nil, http.StatusUnauthorized, "invalid_token"},
		{"bad token", "Bearer nope", `{}`, nil, http.StatusUnauthorized, "invalid_token"},
		{"not JSON", "Bearer good", `redirect_uris=x`, nil, http.StatusBadRequest, "invalid_client_metadata"},
		{"bad redirect", "Bearer good", `{}`, &models.RegistrationError{Code: "invalid_redirect_uri", Description: "nope"},
			http.StatusBadRequest, "invalid_redirect_uri"},
		{"server failure", "Bearer good", `{}`, errors.New("db down"), http.StatusInternalServerError, "server_error"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			r := newRegistrationRouter(t)
			r.svc.err = tt.err

			// Act
			w := r.do(http.MethodPost, "/oauth/register", tt.auth, tt.body)

			// Assert
			assert.Equal(t, tt.wantStatus, w.Code)
			var resp map[string]string
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
			assert.Equal(t, tt.wantError, resp["error"])
			if tt.wantStatus == http.StatusUnauthorized {
				assert.Equal(t, `Bearer error="invalid_token"`, w.Header().Get("WWW-Authenticate"))
			}
			assert.NotContains(t, w.Body.String(), "db down", "internal errors are not leaked")
		})
	}
}

func TestClientConfigurationEndpoint(t *testing.T) {
	// Arrange
	r := newRegistrationRouter(t)

	// Act
	read := r.do(http.MethodGet, "/oauth/register/client_abc", "Bearer good", "")
	update := r.do(http.MethodPut, "/oauth/register/client_abc", "Bearer good", `{"client_id":"client_abc","redirect_uris":["https://p.example/cb"]}`)
	forbidden := r.do(http.MethodDelete, "/oauth/register/client_abc", "Bearer nope", "")
	deleted := r.do(http.MethodDelete, "/oauth/register/client_abc", "Bearer good", "")

	// Assert
	assert.Equal(t, http.StatusOK, read.Code)
	var readBody map[string]interface{}
	require.NoError(t, json.Unmarshal(read.Body.Bytes(), &readBody))
	assert.NotContains(t, readBody, "client_secret", "the secret is never shown again")
	assert.Equal(t, "no-store", read.Header().Get("Cache-Control"))
	assert.Equal(t, http.StatusOK, update.Code)
	assert.Equal(t, "client_abc", r.svc.gotMeta.ClientID)
	assert.Equal(t, http.StatusUnauthorized, forbidden.Code)
	assert.Equal(t, http.StatusNoContent, deleted.Code)
	assert.Equal(t, "client_abc", r.svc.gotClient)
	assert.Contains(t, r.audit.actions(), models.AuditActionClientDeleted)
}

func TestInitialAccessTokenManagement(t *testing.T) {
	// Arrange
	r := newRegistrationRouter(t)
	someone := uuid.NewString()

	// Act
	created := r.do(http.MethodPost, "/v1/client-registration-tokens", "", `{"scopes":["openid"]}`, "X-Test-User", r.admin.String())
	forbidden := r.do(http.MethodPost, "/v1/client-registration-tokens", "", `{"scopes":["openid"]}`, "X-Test-User", someone)
	invalid := r.do(http.MethodPost, "/v1/client-registration-tokens", "", `{}`, "X-Test-User", r.admin.String())
	notFound := r.do(http.MethodDelete, "/v1/client-registration-tokens/"+uuid.NewString(), "", "", "X-Test-User", r.admin.String())

	// Assert
	require.Equal(t, http.StatusCreated, created.Code, created.Body.String())
	assert.Contains(t, created.Body.String(), `"initial_access_token":"iat-value"`)
	assert.Equal(t, "no-store", created.Header().Get("Cache-Control"))
	assert.Equal(t, http.StatusForbidden, forbidden.Code, "requires client:create")
	assert.Equal(t, http.StatusBadRequest, invalid.Code)
	assert.Equal(t, http.StatusNotFound, notFound.Code)
	for _, e := range r.audit.entries {
		assert.NotContains(t, e.Metadata, "initial_access_token", "the token value is never audited")
	}
}
