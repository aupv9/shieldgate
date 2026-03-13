package main

import (
	"context"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"

	"shieldgate/config"
	"shieldgate/internal/database"
	"shieldgate/internal/handlers"
	"shieldgate/internal/middleware"
	"shieldgate/internal/repo/gorm"
	"shieldgate/internal/services"
)

func main() {
	// Load environment variables (optional, for backward compatibility)
	if err := godotenv.Load(); err != nil {
		logrus.Warn("No .env file found, using environment variables")
	}

	// Initialize configuration from YAML file
	cfg, err := config.Load()
	if err != nil {
		logrus.Fatalf("Failed to load configuration: %v", err)
	}

	// Setup logging
	logger := setupLogging(cfg)

	logger.Info("Starting Authorization Server...")

	// Initialize database
	logger.Info("Connecting to database...")
	db, err := database.Initialize(cfg.DatabaseURL)
	if err != nil {
		logger.Fatalf("Failed to initialize database: %v", err)
	}

	// Run database migrations
	if err := database.Migrate(db); err != nil {
		logger.Fatalf("Failed to run database migrations: %v", err)
	}

	// Initialize Redis (optional)
	var redisClient *database.RedisClient
	if cfg.RedisURL != "" {
		redisClient, err = database.InitializeRedis(cfg.RedisURL)
		if err != nil {
			logger.Warnf("Failed to initialize Redis: %v", err)
		} else {
			defer redisClient.Close()
			logger.Info("Redis connection established")
		}
	}

	// Initialize repositories
	repos := gorm.NewRepositories(db)

	// Initialize services
	tenantService := services.NewTenantService(repos, logger)
	userService := services.NewUserService(repos, logger)
	clientService := services.NewClientService(repos, logger)
	authService := services.NewAuthService(repos, cfg, logger)

	// Setup Gin router
	if cfg.GinMode != "" {
		gin.SetMode(cfg.GinMode)
	}

	router := gin.New()

	// Add middleware
	router.Use(gin.Logger())
	router.Use(gin.Recovery())
	router.Use(middleware.CORS(cfg))
	router.Use(middleware.RateLimit(cfg))
	router.Use(middleware.TenantContext(cfg))
	router.Use(middleware.RequestID())

	// Initialize handlers
	tenantHandler := handlers.NewTenantHandler(tenantService, logger)
	userHandler := handlers.NewUserHandler(userService, logger)
	clientHandler := handlers.NewClientHandler(clientService, logger)
	oauthHandler := handlers.NewOAuthHandler(tenantService, userService, clientService, authService, logger)

	// Setup routes
	setupRoutes(router, tenantHandler, userHandler, clientHandler, oauthHandler)

	// Create HTTP server
	server := &http.Server{
		Addr:         fmt.Sprintf(":%s", cfg.Port),
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in a goroutine
	go func() {
		logger.Infof("Server starting on port %s", cfg.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")

	// Give outstanding requests 30 seconds to complete
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Fatalf("Server forced to shutdown: %v", err)
	}

	logger.Info("Server exited")
}

func setupLogging(cfg *config.Config) *logrus.Logger {
	logger := logrus.New()

	// Set log level
	level, err := logrus.ParseLevel(cfg.LogLevel)
	if err != nil {
		level = logrus.InfoLevel
	}
	logger.SetLevel(level)

	// Set log format
	if cfg.LogFormat == "json" {
		logger.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: time.RFC3339,
		})
	} else {
		logger.SetFormatter(&logrus.TextFormatter{
			FullTimestamp: true,
		})
	}

	return logger
}

func setupRoutes(
	router *gin.Engine,
	tenantHandler *handlers.TenantHandler,
	userHandler *handlers.UserHandler,
	clientHandler *handlers.ClientHandler,
	oauthHandler *handlers.OAuthHandler,
) {
	// Health check endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":    "healthy",
			"timestamp": time.Now().UTC(),
			"version":   "1.0.0",
		})
	})

	// OAuth 2.0 and OpenID Connect endpoints (no versioning per spec)
	oauthHandler.RegisterRoutes(router.Group(""))

	// Management API endpoints (versioned)
	api := router.Group("/v1")
	api.Use(middleware.RequireAuth(cfg)) // Require authentication for management APIs
	{
		// Tenant management
		tenantHandler.RegisterRoutes(api.Group("/tenants"))

		// User management
		userHandler.RegisterRoutes(api.Group("/users"))

		// Client management
		clientHandler.RegisterRoutes(api.Group("/clients"))
	}

	// Serve static files and templates
	router.Static("/static", "./static")

	// Add custom template functions
	router.SetFuncMap(template.FuncMap{
		"contains": func(s, substr string) bool {
			return strings.Contains(s, substr)
		},
	})

	router.LoadHTMLGlob("templates/*")
}
