#!/bin/bash

# ShieldGate Essential Commands
# This script provides essential commands for managing ShieldGate

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Docker and Docker Compose are available
check_dependencies() {
    log_info "Checking dependencies..."
    
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed or not in PATH"
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        log_error "Docker Compose is not installed or not in PATH"
        exit 1
    fi
    
    log_success "Dependencies check passed"
}

# Show help
show_help() {
    echo "ShieldGate Essential Commands"
    echo ""
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  setup       Setup development environment"
    echo "  start       Start all services"
    echo "  stop        Stop all services"
    echo "  restart     Restart all services"
    echo "  status      Show service status"
    echo "  logs        Show logs for all services"
    echo "  logs-auth   Show logs for auth server only"
    echo "  health      Check service health"
    echo "  clean       Clean up containers and volumes"
    echo "  rebuild     Rebuild and restart auth server"
    echo "  db-shell    Connect to database shell"
    echo "  test-oauth  Test OAuth flow"
    echo "  backup      Create backup"
    echo "  help        Show this help message"
}

# Setup development environment
setup_env() {
    log_info "Setting up development environment..."
    
    # Create .env if it doesn't exist
    if [ ! -f .env ]; then
        if [ -f .env.example ]; then
            cp .env.example .env
            log_success "Created .env from .env.example"
        else
            log_error ".env.example not found"
            exit 1
        fi
    fi
    
    # Generate secure passwords if they don't exist
    if grep -q "your_secure_password" .env; then
        log_info "Generating secure passwords..."
        
        # Generate random passwords
        POSTGRES_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
        REDIS_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
        JWT_SECRET=$(openssl rand -base64 64 | tr -d "=+/" | cut -c1-64)
        
        # Update .env file
        sed -i.bak "s/your_secure_password_change_me/$POSTGRES_PASSWORD/g" .env
        sed -i.bak "s/your_redis_password_change_me/$REDIS_PASSWORD/g" .env
        sed -i.bak "s/your-super-secret-jwt-key-minimum-32-characters-long-change-me/$JWT_SECRET/g" .env
        
        # Remove backup file
        rm -f .env.bak
        
        log_success "Generated secure passwords"
    fi
    
    # Create necessary directories
    mkdir -p logs backups config/ssl
    
    log_success "Development environment setup complete"
}

# Start services
start_services() {
    log_info "Starting services..."
    docker-compose up -d
    log_success "Services started"
}

# Stop services
stop_services() {
    log_info "Stopping services..."
    docker-compose down
    log_success "Services stopped"
}

# Restart services
restart_services() {
    log_info "Restarting services..."
    docker-compose restart
    log_success "Services restarted"
}

# Show service status
show_status() {
    log_info "Service status:"
    docker-compose ps
}

# Show logs
show_logs() {
    if [ "$1" = "auth" ]; then
        docker-compose logs -f auth-server
    else
        docker-compose logs -f
    fi
}

# Check health
check_health() {
    log_info "Checking service health..."
    
    # Check auth server
    if curl -f http://localhost:8080/health &> /dev/null; then
        log_success "Auth server is healthy"
    else
        log_error "Auth server is not healthy"
    fi
    
    # Check database
    if docker-compose exec -T postgres pg_isready -U ${POSTGRES_USER:-authuser} -d ${POSTGRES_DB:-authdb} &> /dev/null; then
        log_success "Database is ready"
    else
        log_error "Database is not ready"
    fi
    
    # Check Redis
    if docker-compose exec -T redis redis-cli ping &> /dev/null; then
        log_success "Redis is ready"
    else
        log_error "Redis is not ready"
    fi
}

# Clean up
clean_up() {
    log_warning "This will remove all containers and volumes. Are you sure? (y/N)"
    read -r response
    if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        log_info "Cleaning up..."
        docker-compose down -v
        docker system prune -f
        log_success "Cleanup complete"
    else
        log_info "Cleanup cancelled"
    fi
}

# Rebuild auth server
rebuild_auth() {
    log_info "Rebuilding auth server..."
    docker-compose build auth-server
    docker-compose restart auth-server
    log_success "Auth server rebuilt and restarted"
}

# Database shell
db_shell() {
    log_info "Connecting to database shell..."
    docker-compose exec postgres psql -U ${POSTGRES_USER:-authuser} -d ${POSTGRES_DB:-authdb}
}

# Test OAuth flow
test_oauth() {
    log_info "Testing OAuth flow..."
    echo ""
    echo "1. Open this URL in your browser:"
    echo "http://localhost:8080/oauth/authorize?response_type=code&client_id=shieldgate-dev-client&redirect_uri=http://localhost:3000/callback&scope=read%20openid&state=test123&code_challenge=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk&code_challenge_method=S256"
    echo ""
    echo "2. Login with: admin@localhost / admin123"
    echo ""
    echo "3. After authorization, you'll get a code in the redirect URL"
    echo ""
    echo "4. Exchange the code for tokens using:"
    echo "curl -X POST http://localhost:8080/oauth/token \\"
    echo "  -H \"Content-Type: application/x-www-form-urlencoded\" \\"
    echo "  -d \"grant_type=authorization_code&code=YOUR_CODE&client_id=shieldgate-dev-client&client_secret=dev-client-secret-change-in-production&redirect_uri=http://localhost:3000/callback&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk\""
}

# Create backup
create_backup() {
    log_info "Creating backup..."
    
    # Create backup directory
    BACKUP_DIR="backups"
    mkdir -p $BACKUP_DIR
    
    # Generate timestamp
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    
    # Backup database
    docker-compose exec -T postgres pg_dump -U ${POSTGRES_USER:-authuser} ${POSTGRES_DB:-authdb} > $BACKUP_DIR/database_backup_$TIMESTAMP.sql
    gzip $BACKUP_DIR/database_backup_$TIMESTAMP.sql
    
    # Backup configuration
    tar -czf $BACKUP_DIR/config_backup_$TIMESTAMP.tar.gz .env config/ docker-compose*.yml
    
    log_success "Backup created: $BACKUP_DIR/database_backup_$TIMESTAMP.sql.gz"
    log_success "Config backup: $BACKUP_DIR/config_backup_$TIMESTAMP.tar.gz"
}

# Main command handler
main() {
    check_dependencies
    
    case "${1:-help}" in
        setup)
            setup_env
            ;;
        start)
            start_services
            ;;
        stop)
            stop_services
            ;;
        restart)
            restart_services
            ;;
        status)
            show_status
            ;;
        logs)
            show_logs
            ;;
        logs-auth)
            show_logs auth
            ;;
        health)
            check_health
            ;;
        clean)
            clean_up
            ;;
        rebuild)
            rebuild_auth
            ;;
        db-shell)
            db_shell
            ;;
        test-oauth)
            test_oauth
            ;;
        backup)
            create_backup
            ;;
        help|*)
            show_help
            ;;
    esac
}

# Run main function with all arguments
main "$@"