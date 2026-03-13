package config

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/viper"
)

// Config holds all configuration for the application
type Config struct {
	// Database
	DatabaseURL string

	// Redis
	RedisURL string

	// Server
	ServerURL string
	Port      string
	GinMode   string

	// JWT
	JWTSecret string

	// Security
	BcryptCost                int
	AccessTokenDuration       time.Duration
	RefreshTokenDuration      time.Duration
	AuthorizationCodeDuration time.Duration

	// CORS
	CORSAllowedOrigins string
	CORSAllowedMethods string
	CORSAllowedHeaders string

	// Rate Limiting
	RateLimitRequestsPerMinute int

	// Logging
	LogLevel  string
	LogFormat string

	// SMTP (email sending)
	SMTPHost     string
	SMTPPort     int
	SMTPUser     string
	SMTPPassword string
	SMTPFrom     string
	SMTPFromName string
	SMTPUseTLS   bool
}

// Load loads configuration from YAML file
func Load() (*Config, error) {
	// Set the default configuration file name and paths
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("./config")
	viper.AddConfigPath("/etc/auth-server/")

	// Set default values FIRST
	setDefaults()

	// Allow environment variables to override config file values
	viper.AutomaticEnv()

	// Map environment variables to config keys BEFORE reading config
	viper.BindEnv("database.url", "DATABASE_URL")
	viper.BindEnv("redis.url", "REDIS_URL")
	viper.BindEnv("server.url", "SERVER_URL")
	viper.BindEnv("server.port", "PORT")
	viper.BindEnv("server.gin_mode", "GIN_MODE")
	viper.BindEnv("jwt.secret", "JWT_SECRET")
	viper.BindEnv("security.bcrypt_cost", "BCRYPT_COST")
	viper.BindEnv("security.access_token_duration", "ACCESS_TOKEN_DURATION")
	viper.BindEnv("security.refresh_token_duration", "REFRESH_TOKEN_DURATION")
	viper.BindEnv("security.authorization_code_duration", "AUTHORIZATION_CODE_DURATION")
	viper.BindEnv("cors.allowed_origins", "CORS_ALLOWED_ORIGINS")
	viper.BindEnv("cors.allowed_methods", "CORS_ALLOWED_METHODS")
	viper.BindEnv("cors.allowed_headers", "CORS_ALLOWED_HEADERS")
	viper.BindEnv("rate_limit.requests_per_minute", "RATE_LIMIT_REQUESTS_PER_MINUTE")
	viper.BindEnv("logging.level", "LOG_LEVEL")
	viper.BindEnv("logging.format", "LOG_FORMAT")
	viper.BindEnv("smtp.host", "SMTP_HOST")
	viper.BindEnv("smtp.port", "SMTP_PORT")
	viper.BindEnv("smtp.user", "SMTP_USER")
	viper.BindEnv("smtp.password", "SMTP_PASSWORD")
	viper.BindEnv("smtp.from", "SMTP_FROM")
	viper.BindEnv("smtp.from_name", "SMTP_FROM_NAME")
	viper.BindEnv("smtp.use_tls", "SMTP_USE_TLS")

	// Read a configuration file (optional)
	if err := viper.ReadInConfig(); err != nil {
		var configFileNotFoundError viper.ConfigFileNotFoundError
		if errors.As(err, &configFileNotFoundError) {
			// Config file not found; use defaults and environment variables
			fmt.Printf("Warning: Config file not found, using environment variables and defaults\n")
		}
	}

	// Debug: Print environment variables
	fmt.Printf("DEBUG: DATABASE_URL env var: %s\n", os.Getenv("DATABASE_URL"))
	fmt.Printf("DEBUG: Config database.url: %s\n", viper.GetString("database.url"))

	return &Config{
		// Database
		DatabaseURL: viper.GetString("database.url"),

		// Redis
		RedisURL: viper.GetString("redis.url"),

		// Server
		ServerURL: viper.GetString("server.url"),
		Port:      viper.GetString("server.port"),
		GinMode:   viper.GetString("server.gin_mode"),

		// JWT
		JWTSecret: viper.GetString("jwt.secret"),

		// Security
		BcryptCost:                viper.GetInt("security.bcrypt_cost"),
		AccessTokenDuration:       time.Duration(viper.GetInt("security.access_token_duration")) * time.Second,
		RefreshTokenDuration:      time.Duration(viper.GetInt("security.refresh_token_duration")) * time.Second,
		AuthorizationCodeDuration: time.Duration(viper.GetInt("security.authorization_code_duration")) * time.Second,

		// CORS
		CORSAllowedOrigins: viper.GetString("cors.allowed_origins"),
		CORSAllowedMethods: viper.GetString("cors.allowed_methods"),
		CORSAllowedHeaders: viper.GetString("cors.allowed_headers"),

		// Rate Limiting
		RateLimitRequestsPerMinute: viper.GetInt("rate_limit.requests_per_minute"),

		// Logging
		LogLevel:  viper.GetString("logging.level"),
		LogFormat: viper.GetString("logging.format"),

		// SMTP
		SMTPHost:     viper.GetString("smtp.host"),
		SMTPPort:     viper.GetInt("smtp.port"),
		SMTPUser:     viper.GetString("smtp.user"),
		SMTPPassword: viper.GetString("smtp.password"),
		SMTPFrom:     viper.GetString("smtp.from"),
		SMTPFromName: viper.GetString("smtp.from_name"),
		SMTPUseTLS:   viper.GetBool("smtp.use_tls"),
	}, nil
}

// setDefaults sets default configuration values
func setDefaults() {
	// Database defaults
	viper.SetDefault("database.url", "postgres://authuser:password@localhost:5432/authdb?sslmode=disable")

	// Redis defaults
	viper.SetDefault("redis.url", "")

	// Server defaults
	viper.SetDefault("server.url", "http://localhost:8080")
	viper.SetDefault("server.port", "8080")
	viper.SetDefault("server.gin_mode", "debug")

	// JWT defaults
	viper.SetDefault("jwt.secret", "your-super-secret-jwt-key-minimum-32-characters-long")

	// Security defaults
	viper.SetDefault("security.bcrypt_cost", 12)
	viper.SetDefault("security.access_token_duration", 3600)
	viper.SetDefault("security.refresh_token_duration", 2592000)
	viper.SetDefault("security.authorization_code_duration", 600)

	// CORS defaults
	viper.SetDefault("cors.allowed_origins", "*")
	viper.SetDefault("cors.allowed_methods", "GET,POST,PUT,DELETE,OPTIONS")
	viper.SetDefault("cors.allowed_headers", "Origin,Content-Type,Accept,Authorization")

	// Rate limiting defaults
	viper.SetDefault("rate_limit.requests_per_minute", 60)

	// Logging defaults
	viper.SetDefault("logging.level", "info")
	viper.SetDefault("logging.format", "text")

	// SMTP defaults
	viper.SetDefault("smtp.host", "")
	viper.SetDefault("smtp.port", 587)
	viper.SetDefault("smtp.user", "")
	viper.SetDefault("smtp.password", "")
	viper.SetDefault("smtp.from", "noreply@shieldgate.com")
	viper.SetDefault("smtp.from_name", "ShieldGate")
	viper.SetDefault("smtp.use_tls", false)
}
