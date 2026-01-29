# ShieldGate Essential Commands
# Quick commands for managing ShieldGate

param(
    [Parameter(Position=0)]
    [string]$Command = "help"
)

function Write-Info { param([string]$Message) Write-Host "[INFO] $Message" -ForegroundColor Blue }
function Write-Success { param([string]$Message) Write-Host "[SUCCESS] $Message" -ForegroundColor Green }
function Write-Error { param([string]$Message) Write-Host "[ERROR] $Message" -ForegroundColor Red }

switch ($Command.ToLower()) {
    "help" {
        Write-Host "ShieldGate Essential Commands" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Usage: .\essential-commands.ps1 [COMMAND]" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Commands:" -ForegroundColor White
        Write-Host "  fix-db      Fix database connection issue" -ForegroundColor Green
        Write-Host "  start       Start all services" -ForegroundColor Green
        Write-Host "  stop        Stop all services" -ForegroundColor Green
        Write-Host "  restart     Restart all services" -ForegroundColor Green
        Write-Host "  status      Show service status" -ForegroundColor Green
        Write-Host "  logs        Show auth server logs" -ForegroundColor Green
        Write-Host "  health      Check service health" -ForegroundColor Green
        Write-Host "  rebuild     Rebuild auth server" -ForegroundColor Green
        Write-Host "  clean       Clean up containers" -ForegroundColor Green
        Write-Host "  test-oauth  Show OAuth test URLs" -ForegroundColor Green
    }
    
    "fix-db" {
        Write-Info "Fixing database connection issue..."
        
        # Stop auth server
        Write-Info "Stopping auth server..."
        docker-compose stop auth-server
        
        # Remove old container
        Write-Info "Removing old container..."
        docker-compose rm -f auth-server
        
        # Rebuild with no cache
        Write-Info "Rebuilding auth server..."
        docker-compose build --no-cache auth-server
        
        # Start services
        Write-Info "Starting services..."
        docker-compose up -d
        
        # Wait a bit
        Start-Sleep -Seconds 5
        
        # Check logs
        Write-Info "Checking logs..."
        docker-compose logs --tail=10 auth-server
        
        Write-Success "Database fix attempt completed"
    }
    
    "start" {
        Write-Info "Starting services..."
        docker-compose up -d
        if ($LASTEXITCODE -eq 0) { Write-Success "Services started" }
    }
    
    "stop" {
        Write-Info "Stopping services..."
        docker-compose down
        if ($LASTEXITCODE -eq 0) { Write-Success "Services stopped" }
    }
    
    "restart" {
        Write-Info "Restarting services..."
        docker-compose restart
        if ($LASTEXITCODE -eq 0) { Write-Success "Services restarted" }
    }
    
    "status" {
        Write-Info "Service status:"
        docker-compose ps
    }
    
    "logs" {
        Write-Info "Auth server logs:"
        docker-compose logs --tail=20 -f auth-server
    }
    
    "health" {
        Write-Info "Checking service health..."
        try {
            $response = Invoke-WebRequest -Uri "http://localhost:8080/health" -UseBasicParsing -TimeoutSec 5
            if ($response.StatusCode -eq 200) {
                Write-Success "Auth server is healthy"
            }
        } catch {
            Write-Error "Auth server is not healthy"
        }
        
        # Check database
        $dbCheck = docker-compose exec -T postgres pg_isready -U authuser -d authdb 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Database is ready"
        } else {
            Write-Error "Database is not ready"
        }
    }
    
    "rebuild" {
        Write-Info "Rebuilding auth server..."
        docker-compose build auth-server
        docker-compose restart auth-server
        if ($LASTEXITCODE -eq 0) { Write-Success "Auth server rebuilt" }
    }
    
    "clean" {
        Write-Info "Cleaning up containers..."
        docker-compose down -v
        docker system prune -f
        Write-Success "Cleanup complete"
    }
    
    "test-oauth" {
        Write-Info "OAuth Test URLs:"
        Write-Host ""
        Write-Host "1. Authorization URL:" -ForegroundColor Cyan
        Write-Host "http://localhost:8080/oauth/authorize?response_type=code&client_id=shieldgate-dev-client&redirect_uri=http://localhost:3000/callback&scope=read%20openid&state=test123" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "2. Login credentials:" -ForegroundColor Cyan
        Write-Host "Email: admin@localhost" -ForegroundColor Yellow
        Write-Host "Password: admin123" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "3. Health check:" -ForegroundColor Cyan
        Write-Host "http://localhost:8080/health" -ForegroundColor Yellow
    }
    
    default {
        Write-Error "Unknown command: $Command"
        Write-Host "Use 'help' to see available commands"
    }
}