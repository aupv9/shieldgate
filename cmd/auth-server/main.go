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
	"gorm.io/gorm"

	"shieldgate/config"
	"shieldgate/internal/database"
	"shieldgate/internal/handlers"
	"shieldgate/internal/middleware"
	gormrepo "shieldgate/internal/repo/gorm"
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

	// Initialize root context for background workers (cancelled on shutdown)
	rootCtx, cancelRoot := context.WithCancel(context.Background())
	defer cancelRoot()

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
	repos := gormrepo.NewRepositories(db)

	// Initialize services
	auditService := services.NewAuditService(repos.AuditLog, logger)
	emailService := services.NewEmailService(
		repos.EmailTemplate,
		repos.EmailQueue,
		repos.EmailVerification,
		repos.PasswordReset,
		repos.User,
		auditService,
		cfg,
		logger,
	)
	tenantService := services.NewTenantService(repos, logger)
	userService := services.NewUserService(repos, logger)
	clientService := services.NewClientService(repos, logger)
	authService := services.NewAuthService(repos, cfg, logger)

	// Start background email queue processor
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-rootCtx.Done():
				logger.Info("Email queue processor shutting down")
				return
			case <-ticker.C:
				if err := emailService.ProcessQueue(rootCtx); err != nil {
					logger.WithError(err).Error("Failed to process email queue")
				}
			}
		}
	}()

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
	setupRoutes(cfg, db, redisClient, router, tenantHandler, userHandler, clientHandler, oauthHandler)

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

	// Cancel background workers
	cancelRoot()

	// Give outstanding requests 30 seconds to complete
	ctx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

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
	cfg *config.Config,
	db *gorm.DB,
	redisClient *database.RedisClient,
	router *gin.Engine,
	tenantHandler *handlers.TenantHandler,
	userHandler *handlers.UserHandler,
	clientHandler *handlers.ClientHandler,
	oauthHandler *handlers.OAuthHandler,
) {
	// Health check endpoint
	router.GET("/health", func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
		defer cancel()

		status := "ok"
		dbStatus := "ok"
		redisStatus := "ok"
		httpStatus := http.StatusOK

		if db != nil {
			sqlDB, err := db.DB()
			if err != nil || sqlDB.PingContext(ctx) != nil {
				dbStatus = "error"
				status = "degraded"
				httpStatus = http.StatusServiceUnavailable
			}
		} else {
			dbStatus = "disabled"
		}

		if redisClient == nil {
			redisStatus = "disabled"
		} else {
			if err := redisClient.Ping(ctx); err != nil {
				redisStatus = "error"
				status = "degraded"
				httpStatus = http.StatusServiceUnavailable
			}
		}

		c.JSON(httpStatus, gin.H{
			"status":      status,
			"db":          dbStatus,
			"redis":       redisStatus,
			"timestamp":   time.Now().UTC(),
			"version":     "1.0.0",
			"environment": cfg.GinMode,
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
