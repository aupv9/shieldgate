package tests

import (
	"database/sql/driver"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"shieldgate/internal/models"
)

func TestStringArray_Value(t *testing.T) {
	tests := []struct {
		name     string
		array    models.StringArray
		expected driver.Value
		hasError bool
	}{
		{
			name:     "nil array",
			array:    nil,
			expected: nil,
			hasError: false,
		},
		{
			name:     "empty array",
			array:    models.StringArray{},
			expected: []byte("[]"),
			hasError: false,
		},
		{
			name:     "single element",
			array:    models.StringArray{"test"},
			expected: []byte(`["test"]`),
			hasError: false,
		},
		{
			name:     "multiple elements",
			array:    models.StringArray{"read", "write", "admin"},
			expected: []byte(`["read","write","admin"]`),
			hasError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value, err := tt.array.Value()

			if tt.hasError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, value)
			}
		})
	}
}

func TestStringArray_Scan(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected models.StringArray
		hasError bool
	}{
		{
			name:     "nil input",
			input:    nil,
			expected: nil,
			hasError: false,
		},
		{
			name:     "empty JSON array as bytes",
			input:    []byte("[]"),
			expected: models.StringArray{},
			hasError: false,
		},
		{
			name:     "JSON array as bytes",
			input:    []byte(`["read","write"]`),
			expected: models.StringArray{"read", "write"},
			hasError: false,
		},
		{
			name:     "JSON array as string",
			input:    `["admin","user"]`,
			expected: models.StringArray{"admin", "user"},
			hasError: false,
		},
		{
			name:     "invalid JSON",
			input:    []byte(`invalid json`),
			expected: nil,
			hasError: true,
		},
		{
			name:     "unsupported type",
			input:    123,
			expected: nil,
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var array models.StringArray
			err := array.Scan(tt.input)

			if tt.hasError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, array)
			}
		})
	}
}

func TestAuthorizationCode_IsExpired(t *testing.T) {
	tests := []struct {
		name     string
		code     *models.AuthorizationCode
		expected bool
	}{
		{
			name: "not expired",
			code: &models.AuthorizationCode{
				ExpiresAt: time.Now().Add(time.Hour),
			},
			expected: false,
		},
		{
			name: "expired",
			code: &models.AuthorizationCode{
				ExpiresAt: time.Now().Add(-time.Hour),
			},
			expected: true,
		},
		{
			name: "expires exactly now",
			code: &models.AuthorizationCode{
				ExpiresAt: time.Now(),
			},
			expected: true, // Should be considered expired
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.code.IsExpired()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAccessToken_IsExpired(t *testing.T) {
	tests := []struct {
		name     string
		token    *models.AccessToken
		expected bool
	}{
		{
			name: "not expired",
			token: &models.AccessToken{
				ExpiresAt: time.Now().Add(time.Hour),
			},
			expected: false,
		},
		{
			name: "expired",
			token: &models.AccessToken{
				ExpiresAt: time.Now().Add(-time.Hour),
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.token.IsExpired()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRefreshToken_IsExpired(t *testing.T) {
	tests := []struct {
		name     string
		token    *models.RefreshToken
		expected bool
	}{
		{
			name: "not expired",
			token: &models.RefreshToken{
				ExpiresAt: time.Now().Add(time.Hour),
			},
			expected: false,
		},
		{
			name: "expired",
			token: &models.RefreshToken{
				ExpiresAt: time.Now().Add(-time.Hour),
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.token.IsExpired()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestClient_HasRedirectURI(t *testing.T) {
	client := &models.Client{
		RedirectURIs: models.StringArray{
			"http://localhost:3000/callback",
			"https://app.example.com/auth/callback",
		},
	}

	tests := []struct {
		name     string
		uri      string
		expected bool
	}{
		{
			name:     "valid URI - first",
			uri:      "http://localhost:3000/callback",
			expected: true,
		},
		{
			name:     "valid URI - second",
			uri:      "https://app.example.com/auth/callback",
			expected: true,
		},
		{
			name:     "invalid URI",
			uri:      "http://malicious.com/callback",
			expected: false,
		},
		{
			name:     "empty URI",
			uri:      "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := client.HasRedirectURI(tt.uri)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestClient_HasGrantType(t *testing.T) {
	client := &models.Client{
		GrantTypes: models.StringArray{
			"authorization_code",
			"refresh_token",
		},
	}

	tests := []struct {
		name      string
		grantType string
		expected  bool
	}{
		{
			name:      "valid grant type - authorization_code",
			grantType: "authorization_code",
			expected:  true,
		},
		{
			name:      "valid grant type - refresh_token",
			grantType: "refresh_token",
			expected:  true,
		},
		{
			name:      "invalid grant type",
			grantType: "client_credentials",
			expected:  false,
		},
		{
			name:      "empty grant type",
			grantType: "",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := client.HasGrantType(tt.grantType)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestClient_HasScope(t *testing.T) {
	client := &models.Client{
		Scopes: models.StringArray{
			"read",
			"write",
			"openid",
		},
	}

	tests := []struct {
		name     string
		scope    string
		expected bool
	}{
		{
			name:     "valid scope - read",
			scope:    "read",
			expected: true,
		},
		{
			name:     "valid scope - write",
			scope:    "write",
			expected: true,
		},
		{
			name:     "valid scope - openid",
			scope:    "openid",
			expected: true,
		},
		{
			name:     "invalid scope",
			scope:    "admin",
			expected: false,
		},
		{
			name:     "empty scope",
			scope:    "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := client.HasScope(tt.scope)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestJWTClaims_GetExpirationTime(t *testing.T) {
	tests := []struct {
		name     string
		claims   *models.JWTClaims
		expected *jwt.NumericDate
	}{
		{
			name: "with expiration time",
			claims: &models.JWTClaims{
				Exp: 1642694400, // 2022-01-20 12:00:00 UTC
			},
			expected: jwt.NewNumericDate(time.Unix(1642694400, 0)),
		},
		{
			name: "without expiration time",
			claims: &models.JWTClaims{
				Exp: 0,
			},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.claims.GetExpirationTime()
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestJWTClaims_GetIssuedAt(t *testing.T) {
	tests := []struct {
		name     string
		claims   *models.JWTClaims
		expected *jwt.NumericDate
	}{
		{
			name: "with issued at time",
			claims: &models.JWTClaims{
				Iat: 1642690800, // 2022-01-20 11:00:00 UTC
			},
			expected: jwt.NewNumericDate(time.Unix(1642690800, 0)),
		},
		{
			name: "without issued at time",
			claims: &models.JWTClaims{
				Iat: 0,
			},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.claims.GetIssuedAt()
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestJWTClaims_GetIssuer(t *testing.T) {
	claims := &models.JWTClaims{
		Iss: "https://auth.example.com",
	}

	result, err := claims.GetIssuer()
	assert.NoError(t, err)
	assert.Equal(t, "https://auth.example.com", result)
}

func TestJWTClaims_GetSubject(t *testing.T) {
	userID := uuid.New().String()
	claims := &models.JWTClaims{
		Sub: userID,
	}

	result, err := claims.GetSubject()
	assert.NoError(t, err)
	assert.Equal(t, userID, result)
}

func TestJWTClaims_GetAudience(t *testing.T) {
	clientID := uuid.New().String()
	claims := &models.JWTClaims{
		Aud: clientID,
	}

	result, err := claims.GetAudience()
	require.NoError(t, err)
	require.Len(t, result, 1)
	assert.Equal(t, clientID, result[0])
}
