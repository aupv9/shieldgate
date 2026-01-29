#!/bin/bash

# ShieldGate Restore Script
# This script restores database and configuration from backups

set -e

# Load environment variables
if [ -f .env ]; then
    export $(cat .env | grep -v '#' | xargs)
fi

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

# Configuration
BACKUP_DIR="./backups"
DB_NAME=${POSTGRES_DB:-authdb}
DB_USER=${POSTGRES_USER:-authuser}

# Check if backup directory exists
if [ ! -d "$BACKUP_DIR" ]; then
    print_error "Backup directory not found: $BACKUP_DIR"
    exit 1
fi

# Function to list available backups
list_backups() {
    echo ""
    print_status "Available database backups:"
    ls -la $BACKUP_DIR/database_backup_*.sql.gz 2>/dev/null | nl -v0
    echo ""
    print_status "Available configuration backups:"
    ls -la $BACKUP_DIR/config_backup_*.tar.gz 2>/dev/null | nl -v0
    echo ""
}

# Function to restore database
restore_database() {
    local backup_file=$1
    
    if [ ! -f "$backup_file" ]; then
        print_error "Backup file not found: $backup_file"
        return 1
    fi
    
    print_warning "This will overwrite the current database. Are you sure? (y/N)"
    read -r response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        print_status "Database restore cancelled"
        return 0
    fi
    
    print_status "Stopping auth server..."
    docker-compose stop auth-server
    
    print_status "Restoring database from: $backup_file"
    
    # Drop and recreate database
    docker-compose exec postgres psql -U $DB_USER -d postgres -c "DROP DATABASE IF EXISTS $DB_NAME;"
    docker-compose exec postgres psql -U $DB_USER -d postgres -c "CREATE DATABASE $DB_NAME;"
    
    # Restore from backup
    gunzip -c "$backup_file" | docker-compose exec -T postgres psql -U $DB_USER -d $DB_NAME
    
    if [ $? -eq 0 ]; then
        print_success "Database restored successfully"
    else
        print_error "Database restore failed"
        return 1
    fi
    
    print_status "Starting auth server..."
    docker-compose start auth-server
    
    # Wait for auth server to be ready
    sleep 5
    until curl -f http://localhost:8080/health > /dev/null 2>&1; do
        print_status "Waiting for auth server..."
        sleep 2
    done
    
    print_success "Auth server is ready"
}

# Function to restore configuration
restore_config() {
    local backup_file=$1
    
    if [ ! -f "$backup_file" ]; then
        print_error "Backup file not found: $backup_file"
        return 1
    fi
    
    print_warning "This will overwrite current configuration files. Are you sure? (y/N)"
    read -r response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        print_status "Configuration restore cancelled"
        return 0
    fi
    
    print_status "Restoring configuration from: $backup_file"
    
    # Create backup of current config
    CURRENT_DATE=$(date +%Y%m%d_%H%M%S)
    tar -czf $BACKUP_DIR/current_config_backup_$CURRENT_DATE.tar.gz \
        .env config/ docker-compose*.yml 2>/dev/null || true
    
    # Restore configuration
    tar -xzf "$backup_file"
    
    if [ $? -eq 0 ]; then
        print_success "Configuration restored successfully"
        print_status "Current configuration backed up to: current_config_backup_$CURRENT_DATE.tar.gz"
    else
        print_error "Configuration restore failed"
        return 1
    fi
}

# Main script
echo "🔄 ShieldGate Restore Utility"
echo ""

# Check command line arguments
if [ $# -eq 0 ]; then
    list_backups
    echo "Usage: $0 [database|config] [backup_file]"
    echo ""
    echo "Examples:"
    echo "  $0 database $BACKUP_DIR/database_backup_20240122_120000.sql.gz"
    echo "  $0 config $BACKUP_DIR/config_backup_20240122_120000.tar.gz"
    echo ""
    exit 1
fi

RESTORE_TYPE=$1
BACKUP_FILE=$2

case $RESTORE_TYPE in
    "database")
        if [ -z "$BACKUP_FILE" ]; then
            print_error "Please specify a database backup file"
            list_backups
            exit 1
        fi
        restore_database "$BACKUP_FILE"
        ;;
    "config")
        if [ -z "$BACKUP_FILE" ]; then
            print_error "Please specify a configuration backup file"
            list_backups
            exit 1
        fi
        restore_config "$BACKUP_FILE"
        ;;
    *)
        print_error "Invalid restore type. Use 'database' or 'config'"
        exit 1
        ;;
esac

print_success "🎉 Restore completed successfully!"