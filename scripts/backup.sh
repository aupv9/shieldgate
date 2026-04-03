#!/bin/bash

# ShieldGate Backup Script
# This script creates backups of the database and important data

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

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Configuration
BACKUP_DIR="./backups"
DATE=$(date +%Y%m%d_%H%M%S)
DB_NAME=${POSTGRES_DB:-authdb}
DB_USER=${POSTGRES_USER:-authuser}

# Create backup directory
mkdir -p $BACKUP_DIR

print_status "Starting backup process..."

# Database backup
print_status "Creating database backup..."
docker-compose exec -T postgres pg_dump -U $DB_USER -d $DB_NAME --no-password > $BACKUP_DIR/database_backup_$DATE.sql

if [ $? -eq 0 ]; then
    print_success "Database backup created: $BACKUP_DIR/database_backup_$DATE.sql"
else
    print_error "Database backup failed"
    exit 1
fi

# Compress the backup
print_status "Compressing backup..."
gzip $BACKUP_DIR/database_backup_$DATE.sql

if [ $? -eq 0 ]; then
    print_success "Backup compressed: $BACKUP_DIR/database_backup_$DATE.sql.gz"
else
    print_error "Backup compression failed"
fi

# Configuration backup
print_status "Creating configuration backup..."
tar -czf $BACKUP_DIR/config_backup_$DATE.tar.gz \
    .env \
    config/ \
    docker-compose.yml \
    docker-compose.prod.yml \
    docker-compose.dev.yml

if [ $? -eq 0 ]; then
    print_success "Configuration backup created: $BACKUP_DIR/config_backup_$DATE.tar.gz"
else
    print_error "Configuration backup failed"
fi

# Cleanup old backups (keep last 7 days)
print_status "Cleaning up old backups..."
find $BACKUP_DIR -name "database_backup_*.sql.gz" -mtime +7 -delete
find $BACKUP_DIR -name "config_backup_*.tar.gz" -mtime +7 -delete

# Calculate backup size
BACKUP_SIZE=$(du -sh $BACKUP_DIR | cut -f1)
print_success "Backup completed successfully"
print_status "Total backup size: $BACKUP_SIZE"

# List recent backups
print_status "Recent backups:"
ls -lah $BACKUP_DIR/ | tail -10

echo ""
print_success "🎉 Backup process completed!"
echo ""
echo "📁 Backup location: $BACKUP_DIR"
echo "📊 Backup size: $BACKUP_SIZE"
echo ""
echo "💡 To restore from backup:"
echo "   Database: gunzip -c $BACKUP_DIR/database_backup_$DATE.sql.gz | docker-compose exec -T postgres psql -U $DB_USER -d $DB_NAME"
echo "   Config: tar -xzf $BACKUP_DIR/config_backup_$DATE.tar.gz"