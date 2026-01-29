#!/bin/bash

# ShieldGate Test Script
# Comprehensive testing for OAuth flows and API endpoints

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${BLUE}[TEST]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

print_error() {
    echo -e "${RED}[FAIL]${NC} $1"
}

BASE_URL="http://localhost:8080"
CLIENT_ID="shieldgate-dev-client"
CLIENT_SECRET="dev-client-secret-change-in-production"
REDIRECT_URI="http://localhost:3000/callback"

echo "🧪 Testing ShieldGate OAuth 2.0 Server"
echo "========================================"

# Test 1: Health Check
print_status "Testing health endpoint..."
if curl -f -s "$BASE_URL/health" > /dev/null; then
    print_success "Health check passed"
else
    print_error "Health check failed"
    exit 1
fi

# Test 2: Discovery Endpoint
print_status "Testing OpenID Connect discovery..."
DISCOVERY_RESPONSE=$(curl -s "$BASE_URL/.well-known/openid-configuration")
if echo "$DISCOVERY_RESPONSE" | grep -q "authorization_endpoint"; then
    print_success "Discovery endpoint working"
else
    print_error "Discovery endpoint failed"
fi

# Test 3: Authorization Endpoint
print_status "Testing authorization endpoint..."
AUTH_URL="$BASE_URL/oauth/authorize?response_type=code&client_id=$CLIENT_ID&redirect_uri=$REDIRECT_URI&scope=read%20openid&state=test123"
if curl -f -s "$AUTH_URL" > /dev/null; then
    print_success "Authorization endpoint accessible"
else
    print_error "Authorization endpoint failed"
fi

# Test 4: Client Credentials Flow
print_status "Testing client credentials flow..."
TOKEN_RESPONSE=$(curl -s -X POST "$BASE_URL/oauth/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=client_credentials&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET&scope=read")

if echo "$TOKEN_RESPONSE" | grep -q "access_token"; then
    print_success "Client credentials flow working"
    ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)
else
    print_error "Client credentials flow failed"
    echo "Response: $TOKEN_RESPONSE"
fi

# Test 5: Token Introspection
if [ ! -z "$ACCESS_TOKEN" ]; then
    print_status "Testing token introspection..."
    INTROSPECT_RESPONSE=$(curl -s -X POST "$BASE_URL/oauth/introspect" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "token=$ACCESS_TOKEN&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET")
    
    if echo "$INTROSPECT_RESPONSE" | grep -q '"active":true'; then
        print_success "Token introspection working"
    else
        print_error "Token introspection failed"
    fi
fi

# Test 6: API Endpoints
print_status "Testing tenant API..."
TENANT_RESPONSE=$(curl -s -X POST "$BASE_URL/v1/tenants" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -d '{"name":"Test Tenant","domain":"test.example.com"}')

if echo "$TENANT_RESPONSE" | grep -q "id"; then
    print_success "Tenant API working"
else
    print_error "Tenant API failed"
    echo "Response: $TENANT_RESPONSE"
fi

# Test 7: Database Connection
print_status "Testing database connection..."
if docker-compose exec -T postgres pg_isready -U authuser -d authdb > /dev/null 2>&1; then
    print_success "Database connection working"
else
    print_error "Database connection failed"
fi

# Test 8: Redis Connection
print_status "Testing Redis connection..."
if docker-compose exec -T redis redis-cli ping > /dev/null 2>&1; then
    print_success "Redis connection working"
else
    print_error "Redis connection failed"
fi

echo ""
echo "🎉 All tests completed!"
echo ""
echo "📋 OAuth Test URLs:"
echo "Authorization: $AUTH_URL"
echo ""
echo "📖 Next steps:"
echo "1. Open the authorization URL in your browser"
echo "2. Login with admin@localhost / admin123"
echo "3. Complete the OAuth flow"
echo "4. Use the authorization code to get tokens"