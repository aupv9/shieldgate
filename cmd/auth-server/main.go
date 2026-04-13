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
	if err := godotenv.Load(); err != nil {
		logrus.Warn("No .env file found, using environment variables")
	}

	cfg, err := config.Load()
	if err != nil {
		logrus.Fatalf("Failed to load configuration: %v", err)
	}

	logger := setupLogging(cfg)
	logger.Info("Starting Authorization Server...")

	rootCtx, cancelRoot := context.WithCancel(context.Background())
	defer cancelRoot()

	logger.Info("Connecting to database...")
	db, err := database.Initialize(cfg.DatabaseURL)
	if err != nil {
		logger.Fatalf("Failed to initialize database: %v", err)
	}
	if err := database.Migrate(db); err != nil {
		logger.Fatalf("Failed to run database migrations: %v", err)
	}

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

	repos := gormrepo.NewRepositories(db)

	tenantService := services.NewTenantService(repos, logger)
	userService := services.NewUserService(repos, logger)
	clientService := services.NewClientService(repos, logger)
	authService := services.NewAuthService(repos, cfg, logger)
	mfaService := services.NewMFAService(repos, logger)
	sessionService := services.NewSessionService(repos, logger)

	// Background workers
	go runSessionCleanup(rootCtx, sessionService, logger)

	if cfg.GinMode != "" {
		gin.SetMode(cfg.GinMode)
	}
	router := gin.New()
	router.Use(gin.Logger())
	router.Use(gin.Recovery())
	router.Use(middleware.CORS(cfg))
	router.Use(middleware.RateLimit(cfg))
	router.Use(middleware.TenantContext(cfg))
	router.Use(middleware.RequestID())

	tenantHandler := handlers.NewTenantHandler(tenantService, logger)
	userHandler := handlers.NewUserHandler(userService, logger)
	clientHandler := handlers.NewClientHandler(clientService, logger)
	oauthHandler := handlers.NewOAuthHandler(tenantService, userService, clientService, authService, logger)
	mfaHandler := handlers.NewMFAHandler(mfaService, logger)
	sessionHandler := handlers.NewSessionHandler(sessionService, logger)

	setupRoutes(cfg, db, redisClient, router, tenantHandler, userHandler, clientHandler, oauthHandler, mfaHandler, sessionHandler)

	server := &http.Server{
		Addr:         fmt.Sprintf(":%s", cfg.Port),
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		logger.Infof("Server starting on port %s", cfg.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("Failed to start server: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	logger.Info("Shutting down server...")
	cancelRoot()

	ctx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()
	if err := server.Shutdown(ctx); err != nil {
		logger.Fatalf("Server forced to shutdown: %v", err)
	}
	logger.Info("Server exited")
}

func setupLogging(cfg *config.Config) *logrus.Logger {
	logger := logrus.New()
	level, err := logrus.ParseLevel(cfg.LogLevel)
	if err != nil {
		level = logrus.InfoLevel
	}
	logger.SetLevel(level)
	if cfg.LogFormat == "json" {
		logger.SetFormatter(&logrus.JSONFormatter{TimestampFormat: time.RFC3339})
	} else {
		logger.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})
	}
	return logger
}

func runSessionCleanup(ctx context.Context, svc services.SessionService, logger *logrus.Logger) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := svc.CleanupExpired(ctx); err != nil {
				logger.WithError(err).Error("session cleanup failed")
			}
		}
	}
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
	mfaHandler *handlers.MFAHandler,
	sessionHandler *handlers.SessionHandler,
) {
	// Health check
	router.GET("/health", func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
		defer cancel()
		status, dbStatus, redisStatus := "ok", "ok", "ok"
		httpStatus := http.StatusOK
		if db != nil {
			sqlDB, err := db.DB()
			if err != nil || sqlDB.PingContext(ctx) != nil {
				dbStatus = "error"; status = "degraded"; httpStatus = http.StatusServiceUnavailable
			}
		} else {
			dbStatus = "disabled"
		}
		if redisClient == nil {
			redisStatus = "disabled"
		} else if err := redisClient.Ping(ctx); err != nil {
			redisStatus = "error"; status = "degraded"; httpStatus = http.StatusServiceUnavailable
		}
		c.JSON(httpStatus, gin.H{
			"status": status, "db": dbStatus, "redis": redisStatus,
			"timestamp": time.Now().UTC(), "version": "1.0.0",
			"environment": cfg.GinMode,
		})
	})

	// OAuth 2.0 / OIDC endpoints
	oauthHandler.RegisterRoutes(router.Group(""))

	// Management API (authenticated)
	bf := middleware.BruteForceProtection(middleware.BruteForceConfig{
		MaxFailures: 5,
		Window:      15 * time.Minute,
	})

	api := router.Group("/v1")
	api.Use(middleware.RequireAuth(cfg))
	{
		tenantHandler.RegisterRoutes(api.Group("/tenants"))
		userHandler.RegisterRoutes(api.Group("/users"))
		clientHandler.RegisterRoutes(api.Group("/clients"))
		mfaHandler.RegisterRoutes(api.Group("/mfa"))
		sessionHandler.RegisterRoutes(api.Group("/sessions"))
	}

	// Auth endpoints get brute-force protection (applied before RequireAuth)
	auth := router.Group("/v1/auth")
	auth.Use(bf)
	{
		auth.POST("/login", func(c *gin.Context) {
			c.JSON(http.StatusNotImplemented, gin.H{"message": "use /oauth/token"})
		})
	}

	router.Static("/static", "./static")
	router.SetFuncMap(template.FuncMap{
		"contains": strings.Contains,
	})
	router.LoadHTMLGlob("templates/*")
}
