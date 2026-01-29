# Testing Guidelines cho ShieldGate

## Test Structure và Organization

### Test Categories
- **Unit Tests**: Test individual functions và methods
- **Integration Tests**: Test interaction giữa các components
- **OAuth Flow Tests**: Test complete OAuth 2.0 flows
- **Security Tests**: Test security vulnerabilities và edge cases

### Test File Organization
```
internal/
├── handlers/tests/
│   ├── auth_handler_test.go
│   ├── client_handler_test.go
│   └── user_handler_test.go
├── services/tests/
│   ├── auth_service_test.go
│   ├── auth_service_oauth_flow_test.go
│   ├── client_service_test.go
│   └── user_service_test.go
└── models/tests/
    └── models_test.go
```

## Test Patterns và Best Practices

### Test Setup Pattern
```go
func TestMain(m *testing.M) {
    // Setup test database
    testDB := setupTestDB()
    defer cleanupTestDB(testDB)
    
    // Setup test Redis
    testRedis := setupTestRedis()
    defer cleanupTestRedis(testRedis)
    
    // Run tests
    code := m.Run()
    os.Exit(code)
}

func setupTestDB() *gorm.DB {
    db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
    if err != nil {
        panic("failed to connect to test database")
    }
    
    // Auto migrate schemas
    db.AutoMigrate(&models.User{}, &models.Client{}, &models.AuthorizationCode{})
    
    return db
}
```

### Mock Services Pattern
```go
type MockUserService struct {
    users map[string]*models.User
}

func NewMockUserService() *MockUserService {
    return &MockUserService{
        users: make(map[string]*models.User),
    }
}

func (m *MockUserService) GetByID(id string) (*models.User, error) {
    user, exists := m.users[id]
    if !exists {
        return nil, ErrUserNotFound
    }
    return user, nil
}

func (m *MockUserService) Create(user *models.User) error {
    m.users[user.ID] = user
    return nil
}
```

### OAuth Flow Testing
```go
func TestAuthorizationCodeFlow_CompleteFlow_Success(t *testing.T) {
    // Setup
    testServer := setupTestServer()
    defer testServer.Close()
    
    client := &models.Client{
        ID:           "test-client",
        ClientID:     "test-client-id",
        RedirectURIs: []string{"http://localhost:3000/callback"},
        GrantTypes:   []string{"authorization_code", "refresh_token"},
        Scopes:       []string{"read", "write", "openid"},
        IsPublic:     true,
    }
    
    user := &models.User{
        ID:       "test-user",
        Username: "testuser",
        Email:    "test@example.com",
    }
    
    // Step 1: Authorization Request
    codeVerifier := generateCodeVerifier()
    codeChallenge := generateCodeChallenge(codeVerifier)
    
    authURL := fmt.Sprintf("%s/oauth/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=read%%20write%%20openid&state=xyz&code_challenge=%s&code_challenge_method=S256",
        testServer.URL, client.ClientID, url.QueryEscape(client.RedirectURIs[0]), codeChallenge)
    
    // Simulate user login và consent
    authCode := simulateUserAuthAndConsent(t, authURL, user.ID)
    
    // Step 2: Token Exchange
    tokenResp := exchangeCodeForToken(t, testServer.URL, client.ClientID, authCode, codeVerifier, client.RedirectURIs[0])
    
    // Assertions
    assert.NotEmpty(t, tokenResp.AccessToken)
    assert.NotEmpty(t, tokenResp.RefreshToken)
    assert.NotEmpty(t, tokenResp.IDToken)
    assert.Equal(t, "Bearer", tokenResp.TokenType)
    assert.Equal(t, 3600, tokenResp.ExpiresIn)
    
    // Step 3: Validate Access Token
    userInfo := getUserInfo(t, testServer.URL, tokenResp.AccessToken)
    assert.Equal(t, user.ID, userInfo.Sub)
    assert.Equal(t, user.Email, userInfo.Email)
}
```

### Security Testing Patterns
```go
func TestTokenEndpoint_InvalidPKCE_ReturnsError(t *testing.T) {
    testCases := []struct {
        name          string
        codeVerifier  string
        codeChallenge string
        expectedError string
    }{
        {
            name:          "Missing code verifier",
            codeVerifier:  "",
            codeChallenge: "valid-challenge",
            expectedError: "invalid_grant",
        },
        {
            name:          "Invalid code verifier",
            codeVerifier:  "invalid-verifier",
            codeChallenge: "valid-challenge",
            expectedError: "invalid_grant",
        },
        {
            name:          "Mismatched verifier and challenge",
            codeVerifier:  "different-verifier",
            codeChallenge: "different-challenge",
            expectedError: "invalid_grant",
        },
    }
    
    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            // Test implementation
            resp := makeTokenRequest(tc.codeVerifier, tc.codeChallenge)
            assert.Equal(t, tc.expectedError, resp.Error)
        })
    }
}

func TestRateLimit_ExceedsLimit_Returns429(t *testing.T) {
    testServer := setupTestServer()
    defer testServer.Close()
    
    // Make requests up to rate limit
    for i := 0; i < 10; i++ {
        resp := makeTokenRequest(testServer.URL)
        assert.NotEqual(t, 429, resp.StatusCode)
    }
    
    // Next request should be rate limited
    resp := makeTokenRequest(testServer.URL)
    assert.Equal(t, 429, resp.StatusCode)
    assert.Equal(t, "rate_limit_exceeded", resp.Error)
}
```

### Database Testing Patterns
```go
func TestUserRepository_GetByID_UserExists_ReturnsUser(t *testing.T) {
    // Arrange
    db := setupTestDB()
    repo := NewUserRepository(db)
    
    expectedUser := &models.User{
        ID:       "test-id",
        Username: "testuser",
        Email:    "test@example.com",
    }
    db.Create(expectedUser)
    
    // Act
    user, err := repo.GetByID("test-id")
    
    // Assert
    assert.NoError(t, err)
    assert.Equal(t, expectedUser.ID, user.ID)
    assert.Equal(t, expectedUser.Username, user.Username)
    assert.Equal(t, expectedUser.Email, user.Email)
}

func TestUserRepository_GetByID_UserNotExists_ReturnsError(t *testing.T) {
    // Arrange
    db := setupTestDB()
    repo := NewUserRepository(db)
    
    // Act
    user, err := repo.GetByID("non-existent-id")
    
    // Assert
    assert.Error(t, err)
    assert.Nil(t, user)
    assert.Equal(t, ErrUserNotFound, err)
}
```

## Test Utilities và Helpers

### Test Data Generators
```go
func GenerateTestUser() *models.User {
    return &models.User{
        ID:       uuid.New().String(),
        Username: "testuser_" + randomString(8),
        Email:    fmt.Sprintf("test_%s@example.com", randomString(8)),
        Password: "hashedpassword",
    }
}

func GenerateTestClient(isPublic bool) *models.Client {
    client := &models.Client{
        ID:           uuid.New().String(),
        ClientID:     "client_" + randomString(16),
        Name:         "Test Client",
        RedirectURIs: []string{"http://localhost:3000/callback"},
        GrantTypes:   []string{"authorization_code", "refresh_token"},
        Scopes:       []string{"read", "write", "openid"},
        IsPublic:     isPublic,
    }
    
    if !isPublic {
        client.ClientSecret = "secret_" + randomString(32)
    }
    
    return client
}

func GenerateCodeVerifier() string {
    bytes := make([]byte, 32)
    rand.Read(bytes)
    return base64.RawURLEncoding.EncodeToString(bytes)
}

func GenerateCodeChallenge(verifier string) string {
    hash := sha256.Sum256([]byte(verifier))
    return base64.RawURLEncoding.EncodeToString(hash[:])
}
```

### HTTP Test Helpers
```go
func MakeAuthRequest(serverURL, clientID, redirectURI, scope, codeChallenge string) *http.Response {
    authURL := fmt.Sprintf("%s/oauth/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=%s&code_challenge=%s&code_challenge_method=S256",
        serverURL, clientID, url.QueryEscape(redirectURI), url.QueryEscape(scope), codeChallenge)
    
    resp, err := http.Get(authURL)
    if err != nil {
        panic(err)
    }
    return resp
}

func MakeTokenRequest(serverURL, grantType string, params map[string]string) *TokenResponse {
    data := url.Values{}
    data.Set("grant_type", grantType)
    for key, value := range params {
        data.Set(key, value)
    }
    
    resp, err := http.PostForm(serverURL+"/oauth/token", data)
    if err != nil {
        panic(err)
    }
    defer resp.Body.Close()
    
    var tokenResp TokenResponse
    json.NewDecoder(resp.Body).Decode(&tokenResp)
    tokenResp.StatusCode = resp.StatusCode
    
    return &tokenResp
}
```

## Test Coverage Requirements

### Minimum Coverage Targets
- **Overall**: 80% line coverage
- **Critical paths**: 95% coverage (auth flows, token generation)
- **Security functions**: 100% coverage (PKCE validation, token validation)
- **Error handling**: 90% coverage

### Coverage Commands
```bash
# Run tests với coverage
go test -cover ./...

# Generate detailed coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html

# Check coverage thresholds
go test -cover ./... | grep -E "coverage: [0-9]+\.[0-9]+%" | awk '{if($2 < 80.0) exit 1}'
```

## Continuous Integration Testing

### GitHub Actions Test Pipeline
```yaml
name: Test
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:13
        env:
          POSTGRES_PASSWORD: postgres
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
      redis:
        image: redis:6
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
    
    steps:
    - uses: actions/checkout@v2
    - uses: actions/setup-go@v2
      with:
        go-version: 1.21
    
    - name: Run tests
      run: |
        go test -v -cover ./...
        go test -race ./...
    
    - name: Security scan
      run: |
        go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
        gosec ./...
```