package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"

	"shieldgate/config"
	"shieldgate/internal/database"
	"shieldgate/internal/handlers"
	"shieldgate/internal/middleware"
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
	setupLogging(cfg)

	logrus.Info("Starting Authorization Server...")

	// Initialize database
	db, err := database.Initialize(cfg.DatabaseURL)
	if err != nil {
		logrus.Fatalf("Failed to initialize database: %v", err)
	}
	// GORM handles connection management automatically

	// Run database migrations
	if err := database.Migrate(db); err != nil {
		logrus.Fatalf("Failed to run database migrations: %v", err)
	}

	// Initialize Redis (optional)
	var redisClient *database.RedisClient
	if cfg.RedisURL != "" {
		redisClient, err = database.InitializeRedis(cfg.RedisURL)
		if err != nil {
			logrus.Warnf("Failed to initialize Redis: %v", err)
		} else {
			defer redisClient.Close()
			logrus.Info("Redis connection established")
		}
	}

	// Initialize services
	authService := services.NewAuthService(db, redisClient, cfg)
	clientService := services.NewClientService(db)
	userService := services.NewUserService(db)

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

	// Initialize handlers
	authHandler := handlers.NewAuthHandler(authService)
	clientHandler := handlers.NewClientHandler(clientService)
	userHandler := handlers.NewUserHandler(userService)

	// Setup routes
	setupRoutes(router, authHandler, clientHandler, userHandler)

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
		logrus.Infof("Server starting on port %s", cfg.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logrus.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logrus.Info("Shutting down server...")

	// Give outstanding requests 30 seconds to complete
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logrus.Fatalf("Server forced to shutdown: %v", err)
	}

	logrus.Info("Server exited")
}

func setupLogging(cfg *config.Config) {
	// Set log level
	level, err := logrus.ParseLevel(cfg.LogLevel)
	if err != nil {
		level = logrus.InfoLevel
	}
	logrus.SetLevel(level)

	// Set log format
	if cfg.LogFormat == "json" {
		logrus.SetFormatter(&logrus.JSONFormatter{})
	} else {
		logrus.SetFormatter(&logrus.TextFormatter{
			FullTimestamp: true,
		})
	}
}

func setupRoutes(router *gin.Engine, authHandler *handlers.AuthHandler, clientHandler *handlers.ClientHandler, userHandler *handlers.UserHandler) {
	// Health check endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":    "healthy",
			"timestamp": time.Now().UTC(),
			"version":   "1.0.0",
		})
	})

	// OAuth 2.0 endpoints
	oauth := router.Group("/oauth")
	{
		oauth.GET("/authorize", authHandler.Authorize)
		oauth.POST("/token", authHandler.Token)
		oauth.POST("/introspect", authHandler.Introspect)
		oauth.POST("/revoke", authHandler.Revoke)
	}

	// OpenID Connect endpoints
	router.GET("/.well-known/openid-configuration", authHandler.Discovery)
	router.GET("/.well-known/jwks.json", authHandler.JWKS)
	router.GET("/userinfo", authHandler.UserInfo)

	// Management endpoints
	api := router.Group("/api/v1")
	{
		// Client management
		clients := api.Group("/clients")
		{
			clients.POST("", clientHandler.CreateClient)
			clients.GET("/:client_id", clientHandler.GetClient)
			clients.PUT("/:client_id", clientHandler.UpdateClient)
			clients.DELETE("/:client_id", clientHandler.DeleteClient)
			clients.GET("", clientHandler.ListClients)
		}

		// User management
		users := api.Group("/users")
		{
			users.POST("", userHandler.CreateUser)
			users.GET("/:user_id", userHandler.GetUser)
			users.PUT("/:user_id", userHandler.UpdateUser)
			users.DELETE("/:user_id", userHandler.DeleteUser)
			users.GET("", userHandler.ListUsers)
		}
	}

	// Serve static files and templates
	router.Static("/static", "./static")
	router.LoadHTMLGlob("templates/*")
}
