package tests

// oauth_authorize_methods_test.go covers authorization requests sent as a
// form POST (OIDC Core §3.1.2.1) and the rejection of request objects
// (OIDC Core §6), both found by the OpenID conformance suite (roadmap 4.6).

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"shieldgate/internal/handlers"
	"shieldgate/internal/models"
	"shieldgate/tests/utils"
)

const authorizeTestRedirectURI = "https://app.example/callback"

func newAuthorizeRouter(t *testing.T) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)
	tenantID := uuid.New()
	client := &models.Client{
		ID: uuid.New(), TenantID: tenantID, ClientID: "web-app", Name: "Web App",
		RedirectURIs: models.StringArray{authorizeTestRedirectURI},
		GrantTypes:   models.StringArray{"authorization_code"},
		Scopes:       models.StringArray{"openid", "read"},
	}
	clients, tenants := new(MockClientService), new(MockTenantService)
	clients.On("GetByClientID", mock.Anything, tenantID, "web-app").Return(client, nil)
	clients.On("GetByClientID", mock.Anything, tenantID, "").Return(nil, models.ErrClientNotFound)
	clients.On("ValidateRedirectURI", mock.Anything, client, authorizeTestRedirectURI).Return(nil)
	tenants.On("GetByID", mock.Anything, tenantID).Return(&models.Tenant{ID: tenantID, Name: "Acme"}, nil)
	handler := handlers.NewOAuthHandler(utils.CreateTestConfig(), tenants, new(MockUserService), clients, new(MockAuthService), preConsented(), nil, logger)

	router := gin.New()
	router.SetFuncMap(template.FuncMap{"contains": strings.Contains})
	router.LoadHTMLGlob("../../../templates/*")
	router.Use(func(c *gin.Context) {
		c.Set("tenant_id", tenantID)
		c.Next()
	})
	handler.RegisterRoutes(router.Group(""))
	return router
}

func authorizeParams(extra map[string]string) url.Values {
	v := url.Values{
		"response_type": {"code"}, "client_id": {"web-app"}, "redirect_uri": {authorizeTestRedirectURI},
		"scope": {"openid"}, "state": {"st-1"}, "nonce": {"n-1"},
	}
	for k, val := range extra {
		v.Set(k, val)
	}
	return v
}

func TestHandleAuthorize_FormPost_RendersLoginPage(t *testing.T) {
	// Arrange
	router := newAuthorizeRouter(t)
	req := httptest.NewRequest(http.MethodPost, "/oauth/authorize", strings.NewReader(authorizeParams(nil).Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	// Act
	router.ServeHTTP(w, req)

	// Assert
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), `action="/oauth/login"`)
	assert.Contains(t, w.Body.String(), `name="state" value="st-1"`, "the posted parameters are carried into the login form")
}

func TestHandleAuthorize_FormPost_IgnoresQueryParameters(t *testing.T) {
	// Arrange: the form lacks client_id; one in the query must not be used
	router := newAuthorizeRouter(t)
	form := authorizeParams(nil)
	form.Del("client_id")
	req := httptest.NewRequest(http.MethodPost, "/oauth/authorize?client_id=web-app", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	// Act
	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleAuthorize_RequestObject_RejectedAsUnsupported(t *testing.T) {
	tests := []struct {
		param     string
		wantError string
	}{
		{"request", "request_not_supported"},
		{"request_uri", "request_uri_not_supported"},
	}
	for _, tt := range tests {
		t.Run(tt.param, func(t *testing.T) {
			// Arrange
			router := newAuthorizeRouter(t)
			q := authorizeParams(map[string]string{tt.param: "eyJhbGciOiJub25lIn0.eyJzdGF0ZSI6Im90aGVyIn0."})
			w := httptest.NewRecorder()

			// Act
			router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil))

			// Assert
			require.Equal(t, http.StatusFound, w.Code)
			loc, err := url.Parse(w.Header().Get("Location"))
			require.NoError(t, err)
			assert.Equal(t, tt.wantError, loc.Query().Get("error"))
			assert.Equal(t, "st-1", loc.Query().Get("state"))
			assert.Empty(t, loc.Query().Get("code"))
		})
	}
}
