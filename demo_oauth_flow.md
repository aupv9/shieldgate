# OAuth 2.0 Authorization Server Demo

This document demonstrates how to use the Authorization Server's OAuth 2.0 endpoints.

## Prerequisites

1. Start the Authorization Server:
```bash
go run cmd/auth-server/main.go
```

2. The server will start on `http://localhost:8080` by default.

## Demo Flow: OAuth 2.0 Authorization Code Flow with PKCE

### Step 1: Create a Client

First, register an OAuth client:

```bash
curl -X POST http://localhost:8080/api/v1/clients \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Demo Client",
    "redirect_uris": ["http://localhost:3000/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "scopes": ["read", "write", "openid"],
    "is_public": true
  }'
```

Response will include `client_id` that you'll need for the next steps.

### Step 2: Create a User

Register a test user:

```bash
curl -X POST http://localhost:8080/api/v1/users \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "password123"
  }'
```

### Step 3: Generate PKCE Parameters

For a real application, you would generate these programmatically:

```javascript
// Generate code_verifier (43-128 characters)
const codeVerifier = base64URLEncode(crypto.randomBytes(32));

// Generate code_challenge
const codeChallenge = base64URLEncode(sha256(codeVerifier));
```

For this demo, we'll use:
- `code_verifier`: `dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk`
- `code_challenge`: `E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM`

### Step 4: Authorization Request

Direct the user to the authorization endpoint:

```
http://localhost:8080/oauth/authorize?response_type=code&client_id=YOUR_CLIENT_ID&redirect_uri=http://localhost:3000/callback&scope=read%20write%20openid&state=xyz&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256
```

The user will be redirected to a login page, authenticate, and then be redirected back to your `redirect_uri` with an authorization code.

### Step 5: Exchange Authorization Code for Tokens

```bash
curl -X POST http://localhost:8080/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=AUTHORIZATION_CODE&redirect_uri=http://localhost:3000/callback&client_id=YOUR_CLIENT_ID&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
```

Response will include:
- `access_token`: JWT token for API access
- `refresh_token`: Token to refresh the access token
- `id_token`: OpenID Connect identity token (if `openid` scope was requested)
- `expires_in`: Token expiration time in seconds

### Step 6: Use Access Token

Use the access token to access protected resources:

```bash
curl -X GET http://localhost:8080/userinfo \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### Step 7: Refresh Token

When the access token expires, use the refresh token:

```bash
curl -X POST http://localhost:8080/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token&refresh_token=YOUR_REFRESH_TOKEN&client_id=YOUR_CLIENT_ID"
```

### Step 8: Token Introspection

Validate a token:

```bash
curl -X POST http://localhost:8080/oauth/introspect \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=YOUR_ACCESS_TOKEN"
```

### Step 9: Revoke Token

Revoke a token:

```bash
curl -X POST http://localhost:8080/oauth/revoke \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=YOUR_ACCESS_TOKEN&token_type_hint=access_token"
```

## OpenID Connect Discovery

Get the OpenID Connect configuration:

```bash
curl http://localhost:8080/.well-known/openid-configuration
```

## Health Check

Check server health:

```bash
curl http://localhost:8080/health
```

## Notes

- All tokens are JWTs signed with HMAC-SHA256
- PKCE is supported and recommended for public clients
- The server supports both confidential and public clients
- All OAuth 2.0 and OpenID Connect standard endpoints are implemented
- Rate limiting and CORS are configured
- Comprehensive logging and monitoring capabilities are included