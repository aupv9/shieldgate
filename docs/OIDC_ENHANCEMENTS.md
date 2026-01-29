# OIDC Implementation Enhancements

This document provides code examples for enhancing the OIDC implementation with production-ready features.

## 1. RSA Key Support for ID Tokens

### Generate RSA Keys

```bash
# Generate private key
openssl genrsa -out private_key.pem 2048

# Generate public key
openssl rsa -in private_key.pem -pubout -out public_key.pem
```

### Update Config

```go
// config/config.go
type Config struct {
    // ... existing fields
    
    // JWT RSA Keys
    JWTPrivateKeyPath string
    JWTPublicKeyPath  string
    JWTSigningMethod  string // "RS256" or "HS256"
}

func setDefaults() {
    // ... existing defaults
    
    viper.SetDefault("jwt.private_key_path", "./keys/private_key.pem")
    viper.SetDefault("jwt.public_key_path", "./keys/public_key.pem")
    viper.SetDefault("jwt.signing_method", "RS256")
}
```

### Update Auth Service

```go
// internal/services/auth_service.go

import (
    "crypto/rsa"
    "crypto/x509"
    "encoding/pem"
    "os"
)

type AuthService struct {
    // ... existing fields
    privateKey *rsa.PrivateKey
    publicKey  *rsa.PublicKey
    signingMethod string
}

func NewAuthService(db *gorm.DB, redis *database.RedisClient, cfg *config.Config) *AuthService {
    service := &AuthService{
        db:            db,
        redis:         redis,
        cfg:           cfg,
        signingMethod: cfg.JWTSigningMethod,
    }
    
    // Load RSA keys if using RS256
    if cfg.JWTSigningMethod == "RS256" {
        if err := service.loadRSAKeys(cfg.JWTPrivateKeyPath, cfg.JWTPublicKeyPath); err != nil {
            logrus.Fatalf("Failed to load RSA keys: %v", err)
        }
    }
    
    return service
}

func (s *AuthService) loadRSAKeys(privateKeyPath, publicKeyPath string) error {
    // Load private key
    privateKeyData, err := os.ReadFile(privateKeyPath)
    if err != nil {
        return fmt.Errorf("failed to read private key: %w", err)
    }
    
    privateKeyBlock, _ := pem.Decode(privateKeyData)
    if privateKeyBlock == nil {
        return fmt.Errorf("failed to decode private key PEM")
    }
    
    privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
    if err != nil {
        return fmt.Errorf("failed to parse private key: %w", err)
    }
    s.privateKey = privateKey
    
    // Load public key
    publicKeyData, err := os.ReadFile(publicKeyPath)
    if err != nil {
        return fmt.Errorf("failed to read public key: %w", err)
    }
    
    publicKeyBlock, _ := pem.Decode(publicKeyData)
    if publicKeyBlock == nil {
        return fmt.Errorf("failed to decode public key PEM")
    }
    
    publicKeyInterface, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
    if err != nil {
        return fmt.Errorf("failed to parse public key: %w", err)
    }
    
    publicKey, ok := publicKeyInterface.(*rsa.PublicKey)
    if !ok {
        return fmt.Errorf("not an RSA public key")
    }
    s.publicKey = publicKey
    
    return nil
}

func (s *AuthService) generateIDToken(userID uuid.UUID, clientID uuid.UUID, scope string, nonce string) (string, error) {
    user, err := s.getUserByID(userID)
    if err != nil {
        return "", err
    }
    
    now := time.Now()
    claims := &models.JWTClaims{
        Sub:      user.ID.String(),
        Aud:      clientID.String(),
        Iss:      s.cfg.ServerURL,
        Exp:      now.Add(s.cfg.AccessTokenDuration).Unix(),
        Iat:      now.Unix(),
        ClientID: clientID.String(),
        UserID:   user.ID.String(),
    }
    
    // Add nonce if provided
    if nonce != "" {
        claims.Nonce = nonce
    }
    
    // Add claims based on scope
    if strings.Contains(scope, "email") {
        claims.Email = user.Email
    }
    if strings.Contains(scope, "profile") {
        claims.Name = user.Username
    }
    
    // Create token with appropriate signing method
    var token *jwt.Token
    if s.signingMethod == "RS256" {
        token = jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
        return token.SignedString(s.privateKey)
    } else {
        token = jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
        return token.SignedString([]byte(s.cfg.JWTSecret))
    }
}
```

### Update JWKS Endpoint

```go
// internal/handlers/auth_handler.go

func (h *AuthHandler) JWKS(c *gin.Context) {
    if h.authService.GetSigningMethod() == "HS256" {
        // HMAC doesn't expose public keys
        c.JSON(http.StatusOK, gin.H{"keys": []gin.H{}})
        return
    }
    
    // Get public key
    publicKey := h.authService.GetPublicKey()
    
    // Convert to JWK format
    jwk := gin.H{
        "kty": "RSA",
        "use": "sig",
        "kid": "1", // Key ID
        "alg": "RS256",
        "n":   base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
        "e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes()),
    }
    
    c.JSON(http.StatusOK, gin.H{
        "keys": []gin.H{jwk},
    })
}
```

## 2. Nonce Support

### Update Models

```go
// internal/models/models.go

type AuthorizationCode struct {
    // ... existing fields
    Nonce string `json:"nonce" gorm:"size:255"`
}

type JWTClaims struct {
    // ... existing fields
    Nonce string `json:"nonce,omitempty"`
}
```

### Update Authorization Handler

```go
// internal/handlers/auth_handler.go

func (h *AuthHandler) Authorize(c *gin.Context) {
    // ... existing code
    nonce := c.Query("nonce")
    
    // Generate authorization code with nonce
    authCode, err := h.authService.GenerateAuthorizationCode(
        client.ID, userID, redirectURI, scope, codeChallenge, codeChallengeMethod, nonce,
    )
    // ... rest of code
}
```

### Update Token Generation

```go
// internal/services/auth_service.go

func (s *AuthService) GenerateTokens(clientID, userID uuid.UUID, scope string, includeIDToken bool, nonce string) (*models.TokenResponse, error) {
    // ... existing code
    
    if includeIDToken {
        idToken, err := s.generateIDToken(userID, clientID, scope, nonce)
        if err != nil {
            return nil, err
        }
        response.IDToken = idToken
    }
    
    return response, nil
}
```

## 3. Consent Screen

### Create Consent Model

```go
// internal/models/models.go

type Consent struct {
    ID        uuid.UUID      `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
    UserID    uuid.UUID      `json:"user_id" gorm:"type:uuid;not null;index"`
    ClientID  uuid.UUID      `json:"client_id" gorm:"type:uuid;not null;index"`
    Scopes    StringArray    `json:"scopes" gorm:"type:jsonb;not null"`
    CreatedAt time.Time      `json:"created_at" gorm:"autoCreateTime"`
    ExpiresAt *time.Time     `json:"expires_at"`
    
    Client Client `json:"-" gorm:"foreignKey:ClientID;constraint:OnDelete:CASCADE"`
    User   User   `json:"-" gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`
}
```

### Add Consent Template

```html
<!-- templates/consent.html -->
<!DOCTYPE html>
<html>
<head>
    <title>Authorization Request</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 500px; margin: 50px auto; }
        .consent-box { border: 1px solid #ddd; padding: 20px; border-radius: 5px; }
        .scopes { margin: 20px 0; }
        .scope-item { padding: 10px; background: #f5f5f5; margin: 5px 0; border-radius: 3px; }
        .buttons { margin-top: 20px; }
        button { padding: 10px 20px; margin: 5px; cursor: pointer; }
        .approve { background: #4CAF50; color: white; border: none; }
        .deny { background: #f44336; color: white; border: none; }
    </style>
</head>
<body>
    <div class="consent-box">
        <h2>Authorization Request</h2>
        <p><strong>{{.ClientName}}</strong> is requesting access to your account.</p>
        
        <div class="scopes">
            <h3>Requested Permissions:</h3>
            {{range .Scopes}}
            <div class="scope-item">
                <strong>{{.Name}}</strong>: {{.Description}}
            </div>
            {{end}}
        </div>
        
        <form method="POST" action="/oauth/consent">
            <input type="hidden" name="client_id" value="{{.ClientID}}">
            <input type="hidden" name="redirect_uri" value="{{.RedirectURI}}">
            <input type="hidden" name="scope" value="{{.Scope}}">
            <input type="hidden" name="state" value="{{.State}}">
            <input type="hidden" name="code_challenge" value="{{.CodeChallenge}}">
            <input type="hidden" name="code_challenge_method" value="{{.CodeChallengeMethod}}">
            <input type="hidden" name="nonce" value="{{.Nonce}}">
            
            <div class="buttons">
                <button type="submit" name="action" value="approve" class="approve">Approve</button>
                <button type="submit" name="action" value="deny" class="deny">Deny</button>
            </div>
        </form>
    </div>
</body>
</html>
```

### Add Consent Handler

```go
// internal/handlers/auth_handler.go

func (h *AuthHandler) ShowConsent(c *gin.Context) {
    clientID := c.Query("client_id")
    scope := c.Query("scope")
    
    client, err := h.clientService.GetClient(clientID)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client"})
        return
    }
    
    // Parse scopes and get descriptions
    scopes := strings.Split(scope, " ")
    scopeDescriptions := []gin.H{}
    
    scopeMap := map[string]string{
        "openid":  "Verify your identity",
        "profile": "Access your profile information (name, username)",
        "email":   "Access your email address",
        "address": "Access your address information",
        "phone":   "Access your phone number",
    }
    
    for _, s := range scopes {
        if desc, ok := scopeMap[s]; ok {
            scopeDescriptions = append(scopeDescriptions, gin.H{
                "Name":        s,
                "Description": desc,
            })
        }
    }
    
    c.HTML(http.StatusOK, "consent.html", gin.H{
        "ClientID":             clientID,
        "ClientName":           client.Name,
        "RedirectURI":          c.Query("redirect_uri"),
        "Scope":                scope,
        "Scopes":               scopeDescriptions,
        "State":                c.Query("state"),
        "CodeChallenge":        c.Query("code_challenge"),
        "CodeChallengeMethod":  c.Query("code_challenge_method"),
        "Nonce":                c.Query("nonce"),
    })
}

func (h *AuthHandler) HandleConsent(c *gin.Context) {
    action := c.PostForm("action")
    
    if action == "deny" {
        redirectURI := c.PostForm("redirect_uri")
        state := c.PostForm("state")
        h.redirectWithError(c, redirectURI, "access_denied", "User denied authorization", state)
        return
    }
    
    // User approved - save consent and generate authorization code
    userID := h.getCurrentUserID(c)
    clientID := c.PostForm("client_id")
    scope := c.PostForm("scope")
    
    // Save consent
    err := h.authService.SaveConsent(userID, clientID, scope)
    if err != nil {
        logrus.Errorf("Failed to save consent: %v", err)
    }
    
    // Generate authorization code
    // ... (similar to Authorize handler)
}
```

## 4. Dynamic Client Registration

### Add Registration Endpoint

```go
// internal/handlers/client_handler.go

func (h *ClientHandler) RegisterClient(c *gin.Context) {
    var req models.DynamicClientRegistrationRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "error": "invalid_request",
            "error_description": err.Error(),
        })
        return
    }
    
    // Validate request
    if len(req.RedirectURIs) == 0 {
        c.JSON(http.StatusBadRequest, gin.H{
            "error": "invalid_redirect_uri",
            "error_description": "At least one redirect_uri is required",
        })
        return
    }
    
    // Create client
    client, err := h.clientService.CreateDynamicClient(&req)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{
            "error": "server_error",
            "error_description": "Failed to create client",
        })
        return
    }
    
    // Return client credentials
    c.JSON(http.StatusCreated, gin.H{
        "client_id":     client.ClientID,
        "client_secret": client.ClientSecret,
        "client_name":   client.Name,
        "redirect_uris": client.RedirectURIs,
        "grant_types":   client.GrantTypes,
        "response_types": []string{"code"},
        "token_endpoint_auth_method": "client_secret_basic",
    })
}
```

### Add to Routes

```go
// cmd/auth-server/main.go

func setupRoutes(router *gin.Engine, authHandler *handlers.AuthHandler, clientHandler *handlers.ClientHandler, userHandler *handlers.UserHandler) {
    // ... existing routes
    
    // Dynamic client registration
    router.POST("/oauth/register", clientHandler.RegisterClient)
    
    // Consent endpoints
    router.GET("/oauth/consent", authHandler.ShowConsent)
    router.POST("/oauth/consent", authHandler.HandleConsent)
}
```

## 5. Logout Support

### Add Logout Handler

```go
// internal/handlers/auth_handler.go

func (h *AuthHandler) Logout(c *gin.Context) {
    idTokenHint := c.Query("id_token_hint")
    postLogoutRedirectURI := c.Query("post_logout_redirect_uri")
    state := c.Query("state")
    
    // Validate ID token
    if idTokenHint != "" {
        claims, err := h.authService.ValidateIDToken(idTokenHint)
        if err != nil {
            c.JSON(http.StatusBadRequest, gin.H{
                "error": "invalid_request",
                "error_description": "Invalid id_token_hint",
            })
            return
        }
        
        // Revoke all tokens for this user
        userID, _ := uuid.Parse(claims.UserID)
        h.authService.RevokeAllUserTokens(userID)
    }
    
    // Clear session
    // ... (implementation depends on session management)
    
    // Redirect
    if postLogoutRedirectURI != "" {
        redirectURL, _ := url.Parse(postLogoutRedirectURI)
        if state != "" {
            query := redirectURL.Query()
            query.Set("state", state)
            redirectURL.RawQuery = query.Encode()
        }
        c.Redirect(http.StatusFound, redirectURL.String())
    } else {
        c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
    }
}
```

## Configuration Example

```yaml
# config.yaml

jwt:
  secret: "your-secret-key-for-hs256"
  private_key_path: "./keys/private_key.pem"
  public_key_path: "./keys/public_key.pem"
  signing_method: "RS256"  # or "HS256"

security:
  require_consent: true
  consent_expiration_days: 90
  enable_pkce: true
  require_pkce_for_public_clients: true
```

## Testing Enhanced Features

### Test RSA Signed ID Token

```bash
# Get token
TOKEN_RESPONSE=$(curl -s -X POST http://localhost:8080/oauth/token \
  -d "grant_type=authorization_code" \
  -d "code=AUTH_CODE" \
  -d "redirect_uri=http://localhost:3000/callback" \
  -d "client_id=CLIENT_ID" \
  -d "client_secret=CLIENT_SECRET")

# Extract ID token
ID_TOKEN=$(echo $TOKEN_RESPONSE | jq -r '.id_token')

# Verify at jwt.io or using public key
echo $ID_TOKEN
```

### Test JWKS Endpoint

```bash
curl http://localhost:8080/.well-known/jwks.json

# Should return RSA public key in JWK format
```

### Test Dynamic Registration

```bash
curl -X POST http://localhost:8080/oauth/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "My Dynamic Client",
    "redirect_uris": ["https://app.example.com/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"]
  }'
```
