#!/bin/bash

# ShieldGate Development Tools
# Provides additional development utilities

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

show_help() {
    echo "ShieldGate Development Tools"
    echo ""
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  start-tools    Start development tools (Adminer, Redis Commander)"
    echo "  stop-tools     Stop development tools"
    echo "  logs           Show logs for all services"
    echo "  db-reset       Reset database with fresh schema"
    echo "  generate-data  Generate test data"
    echo "  oauth-test     Interactive OAuth flow test"
    echo "  performance    Run performance tests"
    echo "  security       Run security scans"
    echo "  help           Show this help message"
}

start_tools() {
    print_status "Starting development tools..."
    docker-compose --profile dev-tools up -d adminer redis-commander
    
    echo ""
    print_success "Development tools started!"
    echo ""
    echo "📊 Available Tools:"
    echo "   • Adminer (Database): http://localhost:8081"
    echo "   • Redis Commander: http://localhost:8082"
    echo ""
    echo "🔐 Database Connection (Adminer):"
    echo "   • System: PostgreSQL"
    echo "   • Server: postgres"
    echo "   • Username: authuser"
    echo "   • Password: (check .env file)"
    echo "   • Database: authdb"
}

stop_tools() {
    print_status "Stopping development tools..."
    docker-compose --profile dev-tools down
    print_success "Development tools stopped"
}

db_reset() {
    print_warning "This will reset the database and remove all data!"
    read -p "Are you sure? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_status "Resetting database..."
        docker-compose exec postgres psql -U authuser -d authdb -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"
        docker-compose exec postgres psql -U authuser -d authdb -f /docker-entrypoint-initdb.d/01-init.sql
        docker-compose exec postgres psql -U authuser -d authdb -f /docker-entrypoint-initdb.d/02-indexes.sql
        print_success "Database reset completed"
    else
        print_status "Database reset cancelled"
    fi
}

generate_data() {
    print_status "Generating test data..."
    
    # Generate additional tenants
    for i in {1..5}; do
        curl -s -X POST "http://localhost:8080/v1/tenants" \
            -H "Content-Type: application/json" \
            -d "{\"name\":\"Test Tenant $i\",\"domain\":\"tenant$i.example.com\"}" > /dev/null
    done
    
    # Generate additional users
    for i in {1..10}; do
        curl -s -X POST "http://localhost:8080/v1/users" \
            -H "Content-Type: application/json" \
            -H "X-Tenant-ID: localhost" \
            -d "{\"username\":\"user$i\",\"email\":\"user$i@localhost\",\"password\":\"password123\"}" > /dev/null
    done
    
    print_success "Test data generated"
}

oauth_test() {
    print_status "Starting interactive OAuth test..."
    
    CLIENT_ID="shieldgate-dev-client"
    REDIRECT_URI="http://localhost:3000/callback"
    STATE="test-$(date +%s)"
    
    # Generate PKCE parameters
    CODE_VERIFIER=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-43)
    CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | openssl dgst -sha256 -binary | openssl base64 | tr -d "=+/" | cut -c1-43)
    
    AUTH_URL="http://localhost:8080/oauth/authorize?response_type=code&client_id=$CLIENT_ID&redirect_uri=$REDIRECT_URI&scope=read%20write%20openid&state=$STATE&code_challenge=$CODE_CHALLENGE&code_challenge_method=S256"
    
    echo ""
    print_success "OAuth Test Setup Complete!"
    echo ""
    echo "📋 Test Parameters:"
    echo "   • Client ID: $CLIENT_ID"
    echo "   • Redirect URI: $REDIRECT_URI"
    echo "   • State: $STATE"
    echo "   • Code Challenge: $CODE_CHALLENGE"
    echo ""
    echo "🔗 Authorization URL:"
    echo "$AUTH_URL"
    echo ""
    echo "📖 Steps:"
    echo "1. Open the URL above in your browser"
    echo "2. Login with: admin@localhost / admin123"
    echo "3. Authorize the application"
    echo "4. Copy the authorization code from the redirect"
    echo "5. Exchange code for tokens:"
    echo ""
    echo "curl -X POST http://localhost:8080/oauth/token \\"
    echo "  -H \"Content-Type: application/x-www-form-urlencoded\" \\"
    echo "  -d \"grant_type=authorization_code&code=YOUR_CODE&client_id=$CLIENT_ID&client_secret=dev-client-secret-change-in-production&redirect_uri=$REDIRECT_URI&code_verifier=$CODE_VERIFIER\""
}

performance_test() {
    print_status "Running performance tests..."
    
    if ! command -v hey &> /dev/null; then
        print_error "hey tool not found. Install with: go install github.com/rakyll/hey@latest"
        return 1
    fi
    
    echo ""
    print_status "Testing OAuth token endpoint..."
    hey -n 100 -c 10 -m POST \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=client_credentials&client_id=shieldgate-dev-client&client_secret=dev-client-secret-change-in-production&scope=read" \
        http://localhost:8080/oauth/token
    
    echo ""
    print_status "Testing health endpoint..."
    hey -n 1000 -c 50 http://localhost:8080/health
    
    print_success "Performance tests completed"
}

security_scan() {
    print_status "Running security scans..."
    
    # Check for common security issues
    print_status "Checking for exposed secrets..."
    if grep -r "password\|secret\|key" .env 2>/dev/null | grep -v "change_me"; then
        print_warning "Found potential secrets in .env file"
    fi
    
    # Check Docker security
    print_status "Checking Docker security..."
    docker-compose config | grep -i "privileged\|cap_add\|security_opt" || print_success "No privileged containers found"
    
    # Check for default passwords
    print_status "Checking for default passwords..."
    if grep -q "admin123\|password123" scripts/init-db.sql; then
        print_warning "Default passwords found in database initialization"
    fi
    
    print_success "Security scan completed"
}

# Main command handling
case "${1:-help}" in
    start-tools)
        start_tools
        ;;
    stop-tools)
        stop_tools
        ;;
    logs)
        docker-compose logs -f
        ;;
    db-reset)
        db_reset
        ;;
    generate-data)
        generate_data
        ;;
    oauth-test)
        oauth_test
        ;;
    performance)
        performance_test
        ;;
    security)
        security_scan
        ;;
    help|*)
        show_help
        ;;
esac