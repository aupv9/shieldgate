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
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"shieldgate/config"
	"shieldgate/internal/database"
	"shieldgate/internal/handlers"
	"shieldgate/internal/jwtkeys"
	"shieldgate/internal/mfa"
	"shieldgate/internal/middleware"
	"shieldgate/internal/observability"
	gormrepo "shieldgate/internal/repo/gorm"
	"shieldgate/internal/services"
)

// serviceVersion is reported by /health and on traces
const serviceVersion = "1.0.0"

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
	db, err := database.Initialize(cfg.DatabaseURL, logger.GetLevel())
	if err != nil {
		logger.Fatalf("Failed to initialize database: %v", err)
	}

	// Run database migrations
	if err := database.Migrate(db); err != nil {
		logger.Fatalf("Failed to run database migrations: %v", err)
	}

	// Tracing is exported over OTLP when OTEL_EXPORTER_OTLP_ENDPOINT is set
	shutdownTracing, err := observability.SetupTracing(rootCtx, serviceVersion)
	if err != nil {
		logger.Fatalf("Failed to set up tracing: %v", err)
	}
	if observability.TracingEnabled() {
		// Database spans record SQL with placeholders, never parameter values
		if err := db.Use(observability.GormTracing{}); err != nil {
			logger.Fatalf("Failed to enable database tracing: %v", err)
		}
		logger.Info("OpenTelemetry tracing enabled")
	}

	metrics := observability.NewMetrics()
	if sqlDB, err := db.DB(); err == nil {
		metrics.RegisterDB(sqlDB)
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

	// Load JWT signing keys. Outside release mode a missing key file falls
	// back to a throwaway key so local development works out of the box.
	jwtKeys, ephemeralKey, err := jwtkeys.Load(jwtkeys.Options{
		Alg:                  cfg.JWTSigningAlg,
		SigningKeyFile:       cfg.JWTSigningKeyFile,
		VerificationKeyFiles: cfg.JWTVerificationKeyFiles,
		HMACSecret:           cfg.JWTSecret,
		AllowEphemeral:       cfg.GinMode != gin.ReleaseMode,
	})
	if err != nil {
		logger.Fatalf("Failed to load JWT signing keys: %v", err)
	}
	if ephemeralKey {
		logger.Warn("No JWT_SIGNING_KEY_FILE set: using an ephemeral signing key; tokens will not survive a restart or verify across replicas")
	}
	logger.WithFields(logrus.Fields{
		"alg": jwtKeys.Algorithm(),
		"kid": jwtKeys.ActiveKeyID(),
	}).Info("JWT signing key loaded")

	// Initialize repositories
	repos := gormrepo.NewRepositories(db)

	// Initialize services
	auditService := services.NewAuditService(repos.AuditLog, logger)
	// Token, login, MFA and account events go to metrics and the audit log
	recorder := observability.NewRecorder(auditService, metrics, logger)
	emailService := services.NewEmailService(repos.EmailTemplate, repos.EmailQueue, cfg, logger, services.WithEmailMetrics(metrics))
	tenantService := services.NewTenantService(repos, logger)
	userService := services.NewUserService(repos, emailService, cfg.ServerURL, logger)
	clientService := services.NewClientService(repos, logger)
	registrationService := services.NewRegistrationService(repos, clientService, cfg.ServerURL, logger)
	authService := services.NewAuthService(repos, cfg, jwtKeys, logger, services.WithTokenEvents(recorder))
	sessionService := services.NewSessionService(repos.Session, repos.Consent, cfg.SessionDuration, logger)

	// MFA secrets are encrypted at rest with a dedicated key when configured
	mfaMasterKey := mfa.DeriveKey(cfg.JWTSecret)
	if cfg.MFAEncryptionKey != "" {
		if mfaMasterKey, err = mfa.ParseKey(cfg.MFAEncryptionKey); err != nil {
			logger.Fatalf("Invalid MFA_ENCRYPTION_KEY: %v", err)
		}
	} else {
		logger.Warn("No MFA_ENCRYPTION_KEY set: deriving it from JWT_SECRET; rotating JWT_SECRET will invalidate enrolled authenticators")
	}
	mfaKeys, err := mfa.NewKeys(mfaMasterKey)
	if err != nil {
		logger.Fatalf("Failed to initialize MFA keys: %v", err)
	}
	mfaService := services.NewMFAService(repos, mfaKeys, logger)
	roleService := services.NewRoleService(repos.Role, repos.Permission, repos.UserRole, repos.RolePermission, auditService, logger)
	permissionService := services.NewPermissionService(repos.Permission, repos.Role, repos.UserRole, repos.RolePermission, logger)

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

	// Periodically purge expired codes, tokens, SSO sessions and idempotency keys
	go func() {
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-rootCtx.Done():
				logger.Info("Expired data cleanup shutting down")
				return
			case <-ticker.C:
				if err := authService.CleanupExpiredTokens(rootCtx); err != nil {
					logger.WithError(err).Error("Failed to clean up expired tokens")
				}
				if err := sessionService.CleanupExpiredSessions(rootCtx); err != nil {
					logger.WithError(err).Error("Failed to clean up expired sessions")
				}
				if err := repos.Idempotency.DeleteExpired(rootCtx); err != nil {
					logger.WithError(err).Error("Failed to clean up expired idempotency keys")
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
	// Metrics and tracing wrap Recovery so panics are still recorded as 500s
	router.Use(metrics.HTTPMiddleware())
	router.Use(observability.TracingMiddleware(middleware.TenantIDKey))
	router.Use(gin.Logger())
	router.Use(gin.Recovery())
	router.Use(middleware.CORS(cfg))
	router.Use(middleware.RateLimit(cfg))
	// Browser flows reach a tenant through its registered domain
	tenantDomains := middleware.NewDomainTenantResolver(repos.Tenant, time.Minute)
	router.Use(middleware.TenantContext(jwtKeys, tenantDomains))
	router.Use(middleware.RequestID())
	router.Use(observability.RequestContext(middleware.RequestIDKey))

	// Initialize authorization
	superAdminIDs, err := parseUserIDs(cfg.RBACSuperAdminUserIDs)
	if err != nil {
		logger.Fatalf("Invalid RBAC_SUPER_ADMIN_USER_IDS: %v", err)
	}
	if len(superAdminIDs) == 0 {
		logger.Warn("No RBAC super admins configured; tenant and permission management is unreachable")
	}
	authz := middleware.NewAuthorizer(permissionService, superAdminIDs, logger)

	// Initialize handlers
	tenantHandler := handlers.NewTenantHandler(tenantService, logger)
	userHandler := handlers.NewUserHandler(userService, logger)
	accountHandler := handlers.NewAccountHandler(cfg, userService, logger).WithRecorder(recorder)
	clientHandler := handlers.NewClientHandler(clientService, logger)
	oauthHandler := handlers.NewOAuthHandler(cfg, tenantService, userService, clientService, authService, sessionService, mfaService, logger).WithRecorder(recorder)
	mfaHandler := handlers.NewMFAHandler(mfaService, logger).WithRecorder(recorder)
	registrationHandler := handlers.NewRegistrationHandler(registrationService, logger).WithRecorder(recorder)
	rbacHandler := handlers.NewRBACHandler(roleService, permissionService, auditService, logger)
	auditHandler := handlers.NewAuditHandler(auditService, logger)

	// Setup routes
	setupRoutes(cfg, db, redisClient, router, repos.Idempotency, tenantHandler, userHandler, accountHandler, mfaHandler, registrationHandler, clientHandler, oauthHandler, rbacHandler, auditHandler, authService, authz, jwtKeys)

	// Create HTTP server
	server := &http.Server{
		Addr:         fmt.Sprintf(":%s", cfg.Port),
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Metrics get a listener of their own, kept off the public API port
	var metricsServer *http.Server
	if cfg.MetricsAddr != "" {
		metricsMux := http.NewServeMux()
		metricsMux.Handle("/metrics", metrics.Handler())
		metricsServer = &http.Server{Addr: cfg.MetricsAddr, Handler: metricsMux, ReadHeaderTimeout: 5 * time.Second}
		go func() {
			logger.Infof("Metrics listening on %s", cfg.MetricsAddr)
			if err := metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Errorf("Metrics server failed: %v", err)
			}
		}()
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
	if metricsServer != nil {
		if err := metricsServer.Shutdown(ctx); err != nil {
			logger.Warnf("Metrics server shutdown: %v", err)
		}
	}
	// Flush buffered spans
	if err := shutdownTracing(ctx); err != nil {
		logger.Warnf("Tracing shutdown: %v", err)
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
	idempotency middleware.IdempotencyStore,
	tenantHandler *handlers.TenantHandler,
	userHandler *handlers.UserHandler,
	accountHandler *handlers.AccountHandler,
	mfaHandler *handlers.MFAHandler,
	registrationHandler *handlers.RegistrationHandler,
	clientHandler *handlers.ClientHandler,
	oauthHandler *handlers.OAuthHandler,
	rbacHandler *handlers.RBACHandler,
	auditHandler *handlers.AuditHandler,
	authService services.AuthService,
	authz *middleware.Authorizer,
	jwtKeys *jwtkeys.KeySet,
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
			"version":     serviceVersion,
			"environment": cfg.GinMode,
		})
	})

	// OAuth 2.0 and OpenID Connect endpoints (no versioning per spec)
	oauthHandler.RegisterRoutes(router.Group(""))

	// Self-service pages opened from account emails
	accountHandler.RegisterRoutes(router.Group(""))

	// Dynamic client registration (RFC 7591) and client self-management (RFC 7592)
	registrationHandler.RegisterRoutes(router.Group(""))

	// Management API endpoints (versioned)
	api := router.Group("/v1")
	api.Use(middleware.RequireAuth(jwtKeys, authService)) // Require authentication + revocation check for management APIs
	// POSTs carrying an Idempotency-Key are safe to retry for 24 hours
	api.Use(middleware.Idempotency(idempotency, 24*time.Hour))
	{
		// Every route below adds its own RBAC check via authz

		// Tenant management
		tenantHandler.RegisterRoutes(api.Group("/tenants"), authz)

		// User management
		userHandler.RegisterRoutes(api.Group("/users"), authz)

		// Second factors: /v1/users/:user_id/mfa/...
		mfaHandler.RegisterRoutes(api.Group("/users"), authz)

		// Client management
		clientHandler.RegisterRoutes(api.Group("/clients"), authz)

		// Initial access tokens for dynamic client registration
		registrationHandler.RegisterManagementRoutes(api, authz)

		// RBAC: /v1/roles, /v1/permissions, /v1/users/:user_id/{roles,permissions}
		rbacHandler.RegisterRoutes(api, authz)

		// Audit logs: /v1/audit/...
		auditHandler.RegisterRoutes(api, authz)
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

// parseUserIDs parses a comma-separated list of user UUIDs, ignoring blanks
func parseUserIDs(raw string) ([]uuid.UUID, error) {
	var ids []uuid.UUID
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		id, err := uuid.Parse(part)
		if err != nil {
			return nil, fmt.Errorf("%q is not a valid UUID: %w", part, err)
		}
		ids = append(ids, id)
	}
	return ids, nil
}
