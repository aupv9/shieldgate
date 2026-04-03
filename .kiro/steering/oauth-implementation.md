# OAuth 2.0 & OpenID Connect Implementation Guide

## OAuth 2.0 Flow Implementation

### Authorization Code Flow với PKCE
```go
// 1. Authorization Request Handler
func (h *AuthHandler) HandleAuthorize(c *gin.Context) {
    req := &AuthorizeRequest{
        ResponseType:        c.Query("response_type"),
        ClientID:           c.Query("client_id"),
        RedirectURI:        c.Query("redirect_uri"),
        Scope:              c.Query("scope"),
        State:              c.Query("state"),
        CodeChallenge:      c.Query("code_challenge"),
        CodeChallengeMethod: c.Query("code_challenge_method"),
    }
    
    // Validate client và redirect_uri
    client, err := h.clientService.ValidateClient(req.ClientID, req.RedirectURI)
    if err != nil {
        // Redirect với error
        return
    }
    
    // Validate PKCE cho public clients
    if client.IsPublic && (req.CodeChallenge == "" || req.CodeChallengeMethod != "S256") {
        // Return error - PKCE required for public clients
        return
    }
    
    // Render login form hoặc consent page
}

// 2. Token Exchange Handler
func (h *AuthHandler) HandleToken(c *gin.Context) {
    grantType := c.PostForm("grant_type")
    
    switch grantType {
    case "authorization_code":
        h.handleAuthorizationCodeGrant(c)
    case "refresh_token":
        h.handleRefreshTokenGrant(c)
    case "client_credentials":
        h.handleClientCredentialsGrant(c)
    default:
        c.JSON(400, gin.H{"error": "unsupported_grant_type"})
    }
}
```

### PKCE Validation
```go
func (s *AuthService) ValidatePKCE(codeVerifier, codeChallenge, method string) bool {
    if method != "S256" {
        return false
    }
    
    // SHA256 hash của code_verifier
    hash := sha256.Sum256([]byte(codeVerifier))
    // Base64URL encode
    computed := base64.RawURLEncoding.EncodeToString(hash[:])
    
    return computed == codeChallenge
}
```

### JWT Token Generation
```go
type TokenClaims struct {
    UserID   string   `json:"sub"`
    ClientID string   `json:"client_id"`
    Scope    []string `json:"scope"`
    jwt.RegisteredClaims
}

func (s *AuthService) GenerateAccessToken(userID, clientID string, scopes []string) (string, error) {
    claims := TokenClaims{
        UserID:   userID,
        ClientID: clientID,
        Scope:    scopes,
        RegisteredClaims: jwt.RegisteredClaims{
            Issuer:    s.config.Server.URL,
            Subject:   userID,
            Audience:  []string{clientID},
            ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(s.config.Security.AccessTokenDuration) * time.Second)),
            IssuedAt:  jwt.NewNumericDate(time.Now()),
            ID:        uuid.New().String(),
        },
    }
    
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString([]byte(s.config.JWT.Secret))
}
```

## OpenID Connect Implementation

### ID Token Generation
```go
type IDTokenClaims struct {
    Email         string `json:"email,omitempty"`
    EmailVerified bool   `json:"email_verified,omitempty"`
    Name          string `json:"name,omitempty"`
    Picture       string `json:"picture,omitempty"`
    jwt.RegisteredClaims
}

func (s *AuthService) GenerateIDToken(user *models.User, clientID string) (string, error) {
    claims := IDTokenClaims{
        Email:         user.Email,
        EmailVerified: user.EmailVerified,
        Name:          user.Name,
        Picture:       user.Picture,
        RegisteredClaims: jwt.RegisteredClaims{
            Issuer:    s.config.Server.URL,
            Subject:   user.ID,
            Audience:  []string{clientID},
            ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
            IssuedAt:  jwt.NewNumericDate(time.Now()),
        },
    }
    
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString([]byte(s.config.JWT.Secret))
}
```

### UserInfo Endpoint
```go
func (h *AuthHandler) HandleUserInfo(c *gin.Context) {
    // Extract access token từ Authorization header
    authHeader := c.GetHeader("Authorization")
    if !strings.HasPrefix(authHeader, "Bearer ") {
        c.JSON(401, gin.H{"error": "invalid_token"})
        return
    }
    
    tokenString := strings.TrimPrefix(authHeader, "Bearer ")
    
    // Validate và parse token
    claims, err := h.authService.ValidateAccessToken(tokenString)
    if err != nil {
        c.JSON(401, gin.H{"error": "invalid_token"})
        return
    }
    
    // Get user info
    user, err := h.userService.GetByID(claims.UserID)
    if err != nil {
        c.JSON(500, gin.H{"error": "server_error"})
        return
    }
    
    // Return user claims based on requested scopes
    userInfo := h.buildUserInfoResponse(user, claims.Scope)
    c.JSON(200, userInfo)
}
```

### Discovery Endpoint
```go
func (h *AuthHandler) HandleDiscovery(c *gin.Context) {
    baseURL := h.config.Server.URL
    
    discovery := gin.H{
        "issuer":                 baseURL,
        "authorization_endpoint": baseURL + "/oauth/authorize",
        "token_endpoint":         baseURL + "/oauth/token",
        "userinfo_endpoint":      baseURL + "/userinfo",
        "jwks_uri":              baseURL + "/.well-known/jwks.json",
        "introspection_endpoint": baseURL + "/oauth/introspect",
        "revocation_endpoint":    baseURL + "/oauth/revoke",
        
        "response_types_supported": []string{
            "code",
            "id_token",
            "code id_token",
        },
        "grant_types_supported": []string{
            "authorization_code",
            "refresh_token",
            "client_credentials",
        },
        "code_challenge_methods_supported": []string{"S256"},
        "scopes_supported": []string{
            "openid", "profile", "email", "read", "write",
        },
        "claims_supported": []string{
            "sub", "name", "email", "email_verified", "picture",
        },
        "id_token_signing_alg_values_supported": []string{"HS256"},
    }
    
    c.JSON(200, discovery)
}
```

## Security Best Practices

### Token Validation
```go
func (s *AuthService) ValidateAccessToken(tokenString string) (*TokenClaims, error) {
    token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return []byte(s.config.JWT.Secret), nil
    })
    
    if err != nil {
        return nil, err
    }
    
    if claims, ok := token.Claims.(*TokenClaims); ok && token.Valid {
        // Check if token is revoked
        if s.isTokenRevoked(claims.ID) {
            return nil, errors.New("token revoked")
        }
        return claims, nil
    }
    
    return nil, errors.New("invalid token")
}
```

### Scope Validation
```go
func (s *AuthService) ValidateScope(requestedScopes []string, clientScopes []string) []string {
    var validScopes []string
    
    for _, scope := range requestedScopes {
        if contains(clientScopes, scope) {
            validScopes = append(validScopes, scope)
        }
    }
    
    return validScopes
}

func (s *AuthService) RequireScope(requiredScope string, tokenScopes []string) bool {
    return contains(tokenScopes, requiredScope)
}
```

### Rate Limiting cho OAuth Endpoints
```go
func (m *Middleware) OAuthRateLimit() gin.HandlerFunc {
    // Stricter rate limiting cho token endpoint
    tokenLimiter := rate.NewLimiter(rate.Every(time.Minute), 10) // 10 requests per minute
    authLimiter := rate.NewLimiter(rate.Every(time.Minute), 30)  // 30 requests per minute
    
    return func(c *gin.Context) {
        clientIP := c.ClientIP()
        
        var limiter *rate.Limiter
        if strings.Contains(c.Request.URL.Path, "/token") {
            limiter = tokenLimiter
        } else {
            limiter = authLimiter
        }
        
        if !limiter.Allow() {
            c.JSON(429, gin.H{
                "error": "rate_limit_exceeded",
                "error_description": "Too many requests",
            })
            c.Abort()
            return
        }
        
        c.Next()
    }
}
```