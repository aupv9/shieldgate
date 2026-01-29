#!/bin/bash

# ShieldGate Setup Script
# This script sets up the development environment

set -e

echo "🚀 Setting up ShieldGate development environment..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
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

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    print_error "Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    print_status "Creating .env file from template..."
    cp .env.example .env
    
    # Generate secure passwords
    POSTGRES_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
    REDIS_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
    JWT_SECRET=$(openssl rand -base64 64 | tr -d "=+/" | cut -c1-64)
    GRAFANA_PASSWORD=$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-16)
    
    # Update .env file with generated passwords
    sed -i.bak "s/your_secure_password_change_me/$POSTGRES_PASSWORD/g" .env
    sed -i.bak "s/your_redis_password_change_me/$REDIS_PASSWORD/g" .env
    sed -i.bak "s/your-super-secret-jwt-key-minimum-32-characters-long-change-me/$JWT_SECRET/g" .env
    sed -i.bak "s/admin_change_me/$GRAFANA_PASSWORD/g" .env
    
    # Remove backup file
    rm .env.bak
    
    print_success ".env file created with secure passwords"
    print_warning "Please review and update the .env file as needed"
else
    print_status ".env file already exists"
fi

# Create necessary directories
print_status "Creating necessary directories..."
mkdir -p logs
mkdir -p config/ssl
mkdir -p config/grafana/provisioning/dashboards
mkdir -p config/grafana/provisioning/datasources
mkdir -p backups

# Set proper permissions
chmod 755 scripts/*.sh
chmod 600 .env

print_success "Directory structure created"

# Create SSL certificates for development (self-signed)
if [ ! -f config/ssl/cert.pem ]; then
    print_status "Generating self-signed SSL certificates for development..."
    openssl req -x509 -newkey rsa:4096 -keyout config/ssl/key.pem -out config/ssl/cert.pem -days 365 -nodes \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
    print_success "SSL certificates generated"
else
    print_status "SSL certificates already exist"
fi

# Create Grafana datasource configuration
cat > config/grafana/provisioning/datasources/prometheus.yml << EOF
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: true
EOF

# Create Grafana dashboard configuration
cat > config/grafana/provisioning/dashboards/dashboard.yml << EOF
apiVersion: 1

providers:
  - name: 'default'
    orgId: 1
    folder: ''
    type: file
    disableDeletion: false
    updateIntervalSeconds: 10
    allowUiUpdates: true
    options:
      path: /etc/grafana/provisioning/dashboards
EOF

print_success "Grafana configuration created"

# Build and start services
print_status "Building and starting services..."
docker-compose build
docker-compose up -d postgres redis

# Wait for database to be ready
print_status "Waiting for database to be ready..."
sleep 10

# Check if database is ready
until docker-compose exec postgres pg_isready -U ${POSTGRES_USER:-authuser} -d ${POSTGRES_DB:-authdb} > /dev/null 2>&1; do
    print_status "Waiting for database..."
    sleep 2
done

print_success "Database is ready"

# Start the auth server
print_status "Starting auth server..."
docker-compose up -d auth-server

# Wait for auth server to be ready
print_status "Waiting for auth server to be ready..."
sleep 5

# Check if auth server is ready
until curl -f http://localhost:8080/health > /dev/null 2>&1; do
    print_status "Waiting for auth server..."
    sleep 2
done

print_success "Auth server is ready"

# Display status
print_status "Checking service status..."
docker-compose ps

echo ""
print_success "🎉 ShieldGate setup completed successfully!"
echo ""
echo "📋 Service URLs:"
echo "   • Auth Server: http://localhost:8080"
echo "   • Health Check: http://localhost:8080/health"
echo "   • OAuth Authorization: http://localhost:8080/oauth/authorize"
echo ""
echo "🔧 Database Connection:"
echo "   • Host: localhost"
echo "   • Port: 5432"
echo "   • Database: ${POSTGRES_DB:-authdb}"
echo "   • Username: ${POSTGRES_USER:-authuser}"
echo ""
echo "📊 Optional Monitoring (run with --profile monitoring):"
echo "   • Prometheus: http://localhost:9090"
echo "   • Grafana: http://localhost:3000 (admin/admin)"
echo ""
echo "📖 Next steps:"
echo "   1. Review the .env file and update configuration as needed"
echo "   2. Test the OAuth flow: http://localhost:8080/oauth/authorize?response_type=code&client_id=shieldgate-dev-client&redirect_uri=http://localhost:3000/callback&scope=read"
echo "   3. Check logs: docker-compose logs -f auth-server"
echo "   4. Run tests: go test ./..."
echo ""
print_warning "Default credentials (change in production):"
echo "   • Admin user: admin@localhost / admin123"
echo "   • Dev client: shieldgate-dev-client / dev-client-secret-change-in-production"