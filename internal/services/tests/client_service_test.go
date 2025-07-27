package tests

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"shield1/internal/models"
	"shield1/internal/services"
	"shield1/tests/utils"
)

func TestClientService_CreateClient(t *testing.T) {
	db := utils.SetupTestDB(t)
	clientService := services.NewClientService(db)

	tests := []struct {
		name        string
		request     *models.CreateClientRequest
		expectError bool
		errorMsg    string
	}{
		{
			name: "create confidential client",
			request: &models.CreateClientRequest{
				Name:         "Test Confidential Client",
				RedirectURIs: []string{"http://localhost:3000/callback"},
				GrantTypes:   []string{"authorization_code", "refresh_token"},
				Scopes:       []string{"read", "write"},
				IsPublic:     false,
			},
			expectError: false,
		},
		{
			name: "create public client",
			request: &models.CreateClientRequest{
				Name:         "Test Public Client",
				RedirectURIs: []string{"http://localhost:3000/callback"},
				GrantTypes:   []string{"authorization_code"},
				Scopes:       []string{"read"},
				IsPublic:     true,
			},
			expectError: false,
		},
		{
			name: "create client with multiple redirect URIs",
			request: &models.CreateClientRequest{
				Name: "Multi-URI Client",
				RedirectURIs: []string{
					"http://localhost:3000/callback",
					"https://app.example.com/auth/callback",
				},
				GrantTypes: []string{"authorization_code", "refresh_token"},
				Scopes:     []string{"read", "write", "openid"},
				IsPublic:   false,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := clientService.CreateClient(tt.request)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, client)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)
				assert.NotEmpty(t, client.ClientID)
				assert.Equal(t, tt.request.Name, client.Name)
				assert.Equal(t, models.StringArray(tt.request.RedirectURIs), client.RedirectURIs)
				assert.Equal(t, models.StringArray(tt.request.GrantTypes), client.GrantTypes)
				assert.Equal(t, models.StringArray(tt.request.Scopes), client.Scopes)
				assert.Equal(t, tt.request.IsPublic, client.IsPublic)

				if tt.request.IsPublic {
					assert.Empty(t, client.ClientSecret)
				} else {
					assert.NotEmpty(t, client.ClientSecret)
				}

				// Verify client is stored in database
				var dbClient models.Client
				err = db.Where("client_id = ?", client.ClientID).First(&dbClient).Error
				assert.NoError(t, err)
				assert.Equal(t, client.ID, dbClient.ID)
			}
		})
	}
}

func TestClientService_GetClient(t *testing.T) {
	db := utils.SetupTestDB(t)
	clientService := services.NewClientService(db)

	// Create test client
	testClient := utils.CreateTestClient()
	require.NoError(t, db.Create(testClient).Error)

	tests := []struct {
		name        string
		clientID    string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "get existing client",
			clientID:    testClient.ClientID,
			expectError: false,
		},
		{
			name:        "get non-existent client",
			clientID:    "non-existent-client-id",
			expectError: true,
			errorMsg:    "client not found",
		},
		{
			name:        "get client with empty ID",
			clientID:    "",
			expectError: true,
			errorMsg:    "client not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := clientService.GetClient(tt.clientID)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, client)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)
				assert.Equal(t, testClient.ID, client.ID)
				assert.Equal(t, testClient.ClientID, client.ClientID)
				assert.Equal(t, testClient.Name, client.Name)
			}
		})
	}
}

func TestClientService_GetClientByID(t *testing.T) {
	db := utils.SetupTestDB(t)
	clientService := services.NewClientService(db)

	// Create test client
	testClient := utils.CreateTestClient()
	require.NoError(t, db.Create(testClient).Error)

	tests := []struct {
		name        string
		clientID    uuid.UUID
		expectError bool
		errorMsg    string
	}{
		{
			name:        "get existing client by ID",
			clientID:    testClient.ID,
			expectError: false,
		},
		{
			name:        "get non-existent client by ID",
			clientID:    uuid.New(),
			expectError: true,
			errorMsg:    "client not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := clientService.GetClientByID(tt.clientID)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, client)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)
				assert.Equal(t, testClient.ID, client.ID)
				assert.Equal(t, testClient.ClientID, client.ClientID)
			}
		})
	}
}

func TestClientService_UpdateClient(t *testing.T) {
	db := utils.SetupTestDB(t)
	clientService := services.NewClientService(db)

	// Create test client
	testClient := utils.CreateTestClient()
	require.NoError(t, db.Create(testClient).Error)

	tests := []struct {
		name        string
		clientID    string
		request     *models.UpdateClientRequest
		expectError bool
		errorMsg    string
	}{
		{
			name:     "update client name",
			clientID: testClient.ClientID,
			request: &models.UpdateClientRequest{
				Name: "Updated Client Name",
			},
			expectError: false,
		},
		{
			name:     "update redirect URIs",
			clientID: testClient.ClientID,
			request: &models.UpdateClientRequest{
				RedirectURIs: []string{"https://newdomain.com/callback"},
			},
			expectError: false,
		},
		{
			name:     "change from confidential to public",
			clientID: testClient.ClientID,
			request: &models.UpdateClientRequest{
				IsPublic: &[]bool{true}[0],
			},
			expectError: false,
		},
		{
			name:     "update non-existent client",
			clientID: "non-existent-client",
			request: &models.UpdateClientRequest{
				Name: "Updated Name",
			},
			expectError: true,
			errorMsg:    "client not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := clientService.UpdateClient(tt.clientID, tt.request)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, client)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)

				if tt.request.Name != "" {
					assert.Equal(t, tt.request.Name, client.Name)
				}
				if tt.request.RedirectURIs != nil {
					assert.Equal(t, models.StringArray(tt.request.RedirectURIs), client.RedirectURIs)
				}
				if tt.request.IsPublic != nil {
					assert.Equal(t, *tt.request.IsPublic, client.IsPublic)
					if *tt.request.IsPublic {
						assert.Empty(t, client.ClientSecret)
					}
				}
			}
		})
	}
}

func TestClientService_DeleteClient(t *testing.T) {
	db := utils.SetupTestDB(t)
	clientService := services.NewClientService(db)

	// Create test client
	testClient := utils.CreateTestClient()
	require.NoError(t, db.Create(testClient).Error)

	tests := []struct {
		name        string
		clientID    string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "delete existing client",
			clientID:    testClient.ClientID,
			expectError: false,
		},
		{
			name:        "delete non-existent client",
			clientID:    "non-existent-client",
			expectError: true,
			errorMsg:    "client not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := clientService.DeleteClient(tt.clientID)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)

				// Verify client is deleted from database
				var dbClient models.Client
				err = db.Where("client_id = ?", tt.clientID).First(&dbClient).Error
				assert.Error(t, err) // Should not find the client
			}
		})
	}
}

func TestClientService_ListClients(t *testing.T) {
	db := utils.SetupTestDB(t)
	clientService := services.NewClientService(db)

	// Create multiple test clients
	clients := make([]*models.Client, 5)
	for i := 0; i < 5; i++ {
		client := utils.CreateTestClient()
		client.ClientID = client.ClientID + string(rune('0'+i)) // Make unique
		clients[i] = client
		require.NoError(t, db.Create(client).Error)
	}

	tests := []struct {
		name          string
		limit         int
		offset        int
		expectedCount int
		expectedTotal int
	}{
		{
			name:          "list all clients",
			limit:         10,
			offset:        0,
			expectedCount: 5,
			expectedTotal: 5,
		},
		{
			name:          "list with limit",
			limit:         3,
			offset:        0,
			expectedCount: 3,
			expectedTotal: 5,
		},
		{
			name:          "list with offset",
			limit:         10,
			offset:        2,
			expectedCount: 3,
			expectedTotal: 5,
		},
		{
			name:          "list with limit and offset",
			limit:         2,
			offset:        1,
			expectedCount: 2,
			expectedTotal: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientList, total, err := clientService.ListClients(tt.limit, tt.offset)

			assert.NoError(t, err)
			assert.Equal(t, tt.expectedCount, len(clientList))
			assert.Equal(t, tt.expectedTotal, total)

			// Verify client secrets are not exposed
			for _, client := range clientList {
				assert.Empty(t, client.ClientSecret)
			}
		})
	}
}

func TestClientService_ValidateClient(t *testing.T) {
	db := utils.SetupTestDB(t)
	clientService := services.NewClientService(db)

	// Create confidential client with hashed secret
	confidentialClient := utils.CreateTestClient()
	confidentialClient.IsPublic = false
	plainSecret := "test-client-secret"
	hashedSecret, err := bcrypt.GenerateFromPassword([]byte(plainSecret), bcrypt.DefaultCost)
	require.NoError(t, err)
	confidentialClient.ClientSecret = string(hashedSecret)
	require.NoError(t, db.Create(confidentialClient).Error)

	// Create public client
	publicClient := utils.CreateTestClient()
	publicClient.ClientID = "public-client-id"
	publicClient.IsPublic = true
	publicClient.ClientSecret = ""
	require.NoError(t, db.Create(publicClient).Error)

	tests := []struct {
		name         string
		clientID     string
		clientSecret string
		expectError  bool
		errorMsg     string
	}{
		{
			name:         "validate confidential client with correct secret",
			clientID:     confidentialClient.ClientID,
			clientSecret: plainSecret,
			expectError:  false,
		},
		{
			name:         "validate confidential client with wrong secret",
			clientID:     confidentialClient.ClientID,
			clientSecret: "wrong-secret",
			expectError:  true,
			errorMsg:     "invalid client credentials",
		},
		{
			name:         "validate confidential client without secret",
			clientID:     confidentialClient.ClientID,
			clientSecret: "",
			expectError:  true,
			errorMsg:     "client secret required",
		},
		{
			name:         "validate public client without secret",
			clientID:     publicClient.ClientID,
			clientSecret: "",
			expectError:  false,
		},
		{
			name:         "validate public client with secret (should fail)",
			clientID:     publicClient.ClientID,
			clientSecret: "should-not-have-secret",
			expectError:  true,
			errorMsg:     "public client should not have secret",
		},
		{
			name:         "validate non-existent client",
			clientID:     "non-existent-client",
			clientSecret: "",
			expectError:  true,
			errorMsg:     "invalid client",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := clientService.ValidateClient(tt.clientID, tt.clientSecret)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, client)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)
				assert.Equal(t, tt.clientID, client.ClientID)
			}
		})
	}
}

func TestClientService_ValidateRedirectURI(t *testing.T) {
	db := utils.SetupTestDB(t)
	clientService := services.NewClientService(db)

	// Create test client with specific redirect URIs
	testClient := utils.CreateTestClient()
	testClient.RedirectURIs = models.StringArray{
		"http://localhost:3000/callback",
		"https://app.example.com/auth/callback",
	}
	require.NoError(t, db.Create(testClient).Error)

	tests := []struct {
		name        string
		clientID    string
		redirectURI string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "validate allowed redirect URI - first",
			clientID:    testClient.ClientID,
			redirectURI: "http://localhost:3000/callback",
			expectError: false,
		},
		{
			name:        "validate allowed redirect URI - second",
			clientID:    testClient.ClientID,
			redirectURI: "https://app.example.com/auth/callback",
			expectError: false,
		},
		{
			name:        "validate disallowed redirect URI",
			clientID:    testClient.ClientID,
			redirectURI: "http://malicious.com/callback",
			expectError: true,
			errorMsg:    "invalid redirect URI",
		},
		{
			name:        "validate redirect URI for non-existent client",
			clientID:    "non-existent-client",
			redirectURI: "http://localhost:3000/callback",
			expectError: true,
			errorMsg:    "client not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := clientService.ValidateRedirectURI(tt.clientID, tt.redirectURI)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestClientService_GenerateClientID(t *testing.T) {
	db := utils.SetupTestDB(t)
	clientService := services.NewClientService(db)

	// Use reflection to access private method for testing
	// In a real scenario, this would be tested indirectly through CreateClient
	request := &models.CreateClientRequest{
		Name:         "Test Client",
		RedirectURIs: []string{"http://localhost:3000/callback"},
		GrantTypes:   []string{"authorization_code"},
		Scopes:       []string{"read"},
		IsPublic:     true,
	}

	client1, err := clientService.CreateClient(request)
	require.NoError(t, err)

	client2, err := clientService.CreateClient(request)
	require.NoError(t, err)

	// Client IDs should be unique
	assert.NotEqual(t, client1.ClientID, client2.ClientID)
	assert.NotEmpty(t, client1.ClientID)
	assert.NotEmpty(t, client2.ClientID)
}

func TestClientService_GenerateClientSecret(t *testing.T) {
	db := utils.SetupTestDB(t)
	clientService := services.NewClientService(db)

	// Test through CreateClient for confidential clients
	request := &models.CreateClientRequest{
		Name:         "Confidential Client",
		RedirectURIs: []string{"http://localhost:3000/callback"},
		GrantTypes:   []string{"authorization_code"},
		Scopes:       []string{"read"},
		IsPublic:     false,
	}

	client1, err := clientService.CreateClient(request)
	require.NoError(t, err)

	client2, err := clientService.CreateClient(request)
	require.NoError(t, err)

	// Client secrets should be unique and not empty
	assert.NotEqual(t, client1.ClientSecret, client2.ClientSecret)
	assert.NotEmpty(t, client1.ClientSecret)
	assert.NotEmpty(t, client2.ClientSecret)

	// Secrets should be hashed (bcrypt hashes start with $2a$ or similar)
	assert.True(t, len(client1.ClientSecret) > 50) // bcrypt hashes are typically 60 chars
	assert.True(t, len(client2.ClientSecret) > 50)
}
