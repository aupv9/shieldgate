# ShieldGate Essential Commands (PowerShell)
# This script provides essential commands for managing ShieldGate on Windows

param(
    [Parameter(Position=0)]
    [string]$Command = "help"
)

# Helper functions
function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Blue
}

function Write-Success {
    param([string]$Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

# Check if Docker and Docker Compose are available
function Test-Dependencies {
    Write-Info "Checking dependencies..."
    
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Write-Error "Docker is not installed or not in PATH"
        exit 1
    }
    
    if (-not (Get-Command docker-compose -ErrorAction SilentlyContinue)) {
        Write-Error "Docker Compose is not installed or not in PATH"
        exit 1
    }
    
    Write-Success "Dependencies check passed"
}

# Show help
function Show-Help {
    Write-Host "ShieldGate Essential Commands (PowerShell)"
    Write-Host ""
    Write-Host "Usage: .\scripts\essential-commands.ps1 [COMMAND]"
    Write-Host ""
    Write-Host "Commands:"
    Write-Host "  setup       Setup development environment"
    Write-Host "  start       Start all services"
    Write-Host "  stop        Stop all services"
    Write-Host "  restart     Restart all services"
    Write-Host "  status      Show service status"
    Write-Host "  logs        Show logs for all services"
    Write-Host "  logs-auth   Show logs for auth server only"
    Write-Host "  health      Check service health"
    Write-Host "  clean       Clean up containers and volumes"
    Write-Host "  rebuild     Rebuild and restart auth server"
    Write-Host "  db-shell    Connect to database shell"
    Write-Host "  test-oauth  Test OAuth flow"
    Write-Host "  backup      Create backup"
    Write-Host "  help        Show this help message"
}

# Setup development environment
function Initialize-Environment {
    Write-Info "Setting up development environment..."
    
    # Create .env if it doesn't exist
    if (-not (Test-Path .env)) {
        if (Test-Path .env.example) {
            Copy-Item .env.example .env
            Write-Success "Created .env from .env.example"
        } else {
            Write-Error ".env.example not found"
            exit 1
        }
    }
    
    # Generate secure passwords if they don't exist
    $envContent = Get-Content .env -Raw
    if ($envContent -match "your_secure_password") {
        Write-Info "Generating secure passwords..."
        
        # Generate random passwords
        $postgresPassword = [System.Web.Security.Membership]::GeneratePassword(25, 8)
        $redisPassword = [System.Web.Security.Membership]::GeneratePassword(25, 8)
        $jwtSecret = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes([System.Web.Security.Membership]::GeneratePassword(64, 16))).Substring(0,64)
        
        # Update .env file
        $envContent = $envContent -replace 'your_secure_password_change_me', $postgresPassword
        $envContent = $envContent -replace 'your_redis_password_change_me', $redisPassword
        $envContent = $envContent -replace 'your-super-secret-jwt-key-minimum-32-characters-long-change-me', $jwtSecret
        
        Set-Content .env $envContent
        
        Write-Success "Generated secure passwords"
    }
    
    # Create necessary directories
    @('logs', 'backups', 'config\ssl') | ForEach-Object {
        if (-not (Test-Path $_)) {
            New-Item -ItemType Directory -Path $_ -Force | Out-Null
        }
    }
    
    Write-Success "Development environment setup complete"
}

# Start services
function Start-Services {
    Write-Info "Starting services..."
    docker-compose up -d
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Services started"
    } else {
        Write-Error "Failed to start services"
    }
}

# Stop services
function Stop-Services {
    Write-Info "Stopping services..."
    docker-compose down
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Services stopped"
    } else {
        Write-Error "Failed to stop services"
    }
}

# Restart services
function Restart-Services {
    Write-Info "Restarting services..."
    docker-compose restart
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Services restarted"
    } else {
        Write-Error "Failed to restart services"
    }
}

# Show service status
function Show-Status {
    Write-Info "Service status:"
    docker-compose ps
}

# Show logs
function Show-Logs {
    param([string]$Service = "")
    
    if ($Service -eq "auth") {
        docker-compose logs -f auth-server
    } else {
        docker-compose logs -f
    }
}

# Check health
function Test-Health {
    Write-Info "Checking service health..."
    
    # Check auth server
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:8080/health" -UseBasicParsing -TimeoutSec 5
        if ($response.StatusCode -eq 200) {
            Write-Success "Auth server is healthy"
        } else {
            Write-Error "Auth server returned status code: $($response.StatusCode)"
        }
    } catch {
        Write-Error "Auth server is not healthy: $($_.Exception.Message)"
    }
    
    # Check database
    $dbCheck = docker-compose exec -T postgres pg_isready -U authuser -d authdb 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Database is ready"
    } else {
        Write-Error "Database is not ready"
    }
    
    # Check Redis
    $redisCheck = docker-compose exec -T redis redis-cli ping 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Redis is ready"
    } else {
        Write-Error "Redis is not ready"
    }
}

# Clean up
function Remove-All {
    Write-Warning "This will remove all containers and volumes. Are you sure? (y/N)"
    $response = Read-Host
    if ($response -match '^[yY]([eE][sS])?$') {
        Write-Info "Cleaning up..."
        docker-compose down -v
        docker system prune -f
        Write-Success "Cleanup complete"
    } else {
        Write-Info "Cleanup cancelled"
    }
}

# Rebuild auth server
function Rebuild-AuthServer {
    Write-Info "Rebuilding auth server..."
    docker-compose build auth-server
    docker-compose restart auth-server
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Auth server rebuilt and restarted"
    } else {
        Write-Error "Failed to rebuild auth server"
    }
}

# Database shell
function Connect-Database {
    Write-Info "Connecting to database shell..."
    docker-compose exec postgres psql -U authuser -d authdb
}

# Test OAuth flow
function Test-OAuthFlow {
    Write-Info "Testing OAuth flow..."
    Write-Host ""
    Write-Host "1. Open this URL in your browser:" -ForegroundColor Cyan
    Write-Host "http://localhost:8080/oauth/authorize?response_type=code&client_id=shieldgate-dev-client&redirect_uri=http://localhost:3000/callback&scope=read%20openid&state=test123&code_challenge=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk&code_challenge_method=S256" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "2. Login with: admin@localhost / admin123" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "3. After authorization, you'll get a code in the redirect URL" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "4. Exchange the code for tokens using:" -ForegroundColor Cyan
    Write-Host 'curl -X POST http://localhost:8080/oauth/token \' -ForegroundColor Yellow
    Write-Host '  -H "Content-Type: application/x-www-form-urlencoded" \' -ForegroundColor Yellow
    Write-Host '  -d "grant_type=authorization_code&code=YOUR_CODE&client_id=shieldgate-dev-client&client_secret=dev-client-secret-change-in-production&redirect_uri=http://localhost:3000/callback&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"' -ForegroundColor Yellow
}

# Create backup
function New-Backup {
    Write-Info "Creating backup..."
    
    # Create backup directory
    $backupDir = "backups"
    if (-not (Test-Path $backupDir)) {
        New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
    }
    
    # Generate timestamp
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    
    # Backup database
    $dbBackupFile = "$backupDir\database_backup_$timestamp.sql"
    docker-compose exec -T postgres pg_dump -U authuser authdb > $dbBackupFile
    
    # Compress backup
    Compress-Archive -Path $dbBackupFile -DestinationPath "$dbBackupFile.zip" -Force
    Remove-Item $dbBackupFile
    
    # Backup configuration
    $configFiles = @('.env', 'config', 'docker-compose*.yml')
    $configBackupFile = "$backupDir\config_backup_$timestamp.zip"
    Compress-Archive -Path $configFiles -DestinationPath $configBackupFile -Force
    
    Write-Success "Database backup created: $dbBackupFile.zip"
    Write-Success "Config backup created: $configBackupFile"
}

# Main command handler
function Invoke-Command {
    param([string]$Cmd)
    
    Test-Dependencies
    
    switch ($Cmd.ToLower()) {
        "setup" { Initialize-Environment }
        "start" { Start-Services }
        "stop" { Stop-Services }
        "restart" { Restart-Services }
        "status" { Show-Status }
        "logs" { Show-Logs }
        "logs-auth" { Show-Logs -Service "auth" }
        "health" { Test-Health }
        "clean" { Remove-All }
        "rebuild" { Rebuild-AuthServer }
        "db-shell" { Connect-Database }
        "test-oauth" { Test-OAuthFlow }
        "backup" { New-Backup }
        default { Show-Help }
    }
}

# Add required assembly for password generation
Add-Type -AssemblyName System.Web

# Run the command
Invoke-Command -Cmd $Command