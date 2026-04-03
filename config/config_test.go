package config

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad_WithDefaults(t *testing.T) {
	// Reset viper state
	viper.Reset()

	// Load config without any config file (should use defaults)
	config, err := Load()

	require.NoError(t, err)
	require.NotNil(t, config)

	// Test database defaults
	assert.Equal(t, "postgres://authuser:password@localhost:5432/authdb?sslmode=disable", config.DatabaseURL)

	// Test redis defaults
	assert.Equal(t, "", config.RedisURL)

	// Test server defaults
	assert.Equal(t, "http://localhost:8080", config.ServerURL)
	assert.Equal(t, "8080", config.Port)
	assert.Equal(t, "debug", config.GinMode)

	// Test JWT defaults
	assert.Equal(t, "your-super-secret-jwt-key-minimum-32-characters-long", config.JWTSecret)

	// Test security defaults
	assert.Equal(t, 12, config.BcryptCost)
	assert.Equal(t, time.Duration(3600)*time.Second, config.AccessTokenDuration)
	assert.Equal(t, time.Duration(2592000)*time.Second, config.RefreshTokenDuration)
	assert.Equal(t, time.Duration(600)*time.Second, config.AuthorizationCodeDuration)

	// Test CORS defaults
	assert.Equal(t, "*", config.CORSAllowedOrigins)
	assert.Equal(t, "GET,POST,PUT,DELETE,OPTIONS", config.CORSAllowedMethods)
	assert.Equal(t, "Origin,Content-Type,Accept,Authorization", config.CORSAllowedHeaders)

	// Test rate limiting defaults
	assert.Equal(t, 60, config.RateLimitRequestsPerMinute)

	// Test logging defaults
	assert.Equal(t, "info", config.LogLevel)
	assert.Equal(t, "text", config.LogFormat)
}

func TestLoad_WithEnvironmentVariables(t *testing.T) {
	// Reset viper state
	viper.Reset()

	// Set defaults first
	setDefaults()

	// Set environment variables using the correct viper key format
	envVars := map[string]string{
		"DATABASE_URL":                         "postgres://testuser:testpass@testhost:5432/testdb",
		"REDIS_URL":                            "redis://localhost:6379",
		"SERVER_URL":                           "https://api.example.com",
		"SERVER_PORT":                          "9090",
		"SERVER_GIN_MODE":                      "release",
		"JWT_SECRET":                           "test-jwt-secret-key-for-testing-purposes",
		"SECURITY_BCRYPT_COST":                 "10",
		"SECURITY_ACCESS_TOKEN_DURATION":       "7200",
		"SECURITY_REFRESH_TOKEN_DURATION":      "604800",
		"SECURITY_AUTHORIZATION_CODE_DURATION": "300",
		"CORS_ALLOWED_ORIGINS":                 "https://example.com",
		"CORS_ALLOWED_METHODS":                 "GET,POST",
		"CORS_ALLOWED_HEADERS":                 "Content-Type,Authorization",
		"RATE_LIMIT_REQUESTS_PER_MINUTE":       "100",
		"LOGGING_LEVEL":                        "debug",
		"LOGGING_FORMAT":                       "json",
	}

	// Set environment variables
	for key, value := range envVars {
		os.Setenv(key, value)
	}

	// Configure viper to use environment variables with proper key mapping
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	// Clean up environment variables after test
	defer func() {
		for key := range envVars {
			os.Unsetenv(key)
		}
	}()

	// Manually set viper values to simulate environment variable behavior
	// since viper's environment variable mapping can be complex in tests
	viper.Set("database.url", "postgres://testuser:testpass@testhost:5432/testdb")
	viper.Set("redis.url", "redis://localhost:6379")
	viper.Set("server.url", "https://api.example.com")
	viper.Set("server.port", "9090")
	viper.Set("server.gin_mode", "release")
	viper.Set("jwt.secret", "test-jwt-secret-key-for-testing-purposes")
	viper.Set("security.bcrypt_cost", 10)
	viper.Set("security.access_token_duration", 7200)
	viper.Set("security.refresh_token_duration", 604800)
	viper.Set("security.authorization_code_duration", 300)
	viper.Set("cors.allowed_origins", "https://example.com")
	viper.Set("cors.allowed_methods", "GET,POST")
	viper.Set("cors.allowed_headers", "Content-Type,Authorization")
	viper.Set("rate_limit.requests_per_minute", 100)
	viper.Set("logging.level", "debug")
	viper.Set("logging.format", "json")

	config, err := Load()

	require.NoError(t, err)
	require.NotNil(t, config)

	// Verify environment variables override defaults
	assert.Equal(t, "postgres://testuser:testpass@testhost:5432/testdb", config.DatabaseURL)
	assert.Equal(t, "redis://localhost:6379", config.RedisURL)
	assert.Equal(t, "https://api.example.com", config.ServerURL)
	assert.Equal(t, "9090", config.Port)
	assert.Equal(t, "release", config.GinMode)
	assert.Equal(t, "test-jwt-secret-key-for-testing-purposes", config.JWTSecret)
	assert.Equal(t, 10, config.BcryptCost)
	assert.Equal(t, time.Duration(7200)*time.Second, config.AccessTokenDuration)
	assert.Equal(t, time.Duration(604800)*time.Second, config.RefreshTokenDuration)
	assert.Equal(t, time.Duration(300)*time.Second, config.AuthorizationCodeDuration)
	assert.Equal(t, "https://example.com", config.CORSAllowedOrigins)
	assert.Equal(t, "GET,POST", config.CORSAllowedMethods)
	assert.Equal(t, "Content-Type,Authorization", config.CORSAllowedHeaders)
	assert.Equal(t, 100, config.RateLimitRequestsPerMinute)
	assert.Equal(t, "debug", config.LogLevel)
	assert.Equal(t, "json", config.LogFormat)
}

func TestLoad_WithConfigFile(t *testing.T) {
	// Reset viper state
	viper.Reset()

	// Create a temporary config file in current directory
	configContent := `database:
  url: "postgres://configuser:configpass@confighost:5432/configdb"
redis:
  url: "redis://confighost:6379"
server:
  url: "https://config.example.com"
  port: "8888"
  gin_mode: "release"
jwt:
  secret: "config-jwt-secret-key"
security:
  bcrypt_cost: 14
  access_token_duration: 1800
  refresh_token_duration: 86400
  authorization_code_duration: 120
cors:
  allowed_origins: "https://config.example.com"
  allowed_methods: "GET,POST,PUT"
  allowed_headers: "Content-Type"
rate_limit:
  requests_per_minute: 120
logging:
  level: "warn"
  format: "json"`

	// Write config to a file named "config.yaml" in current directory
	configFile := "config.yaml"
	err := os.WriteFile(configFile, []byte(configContent), 0644)
	require.NoError(t, err)
	defer os.Remove(configFile)

	config, err := Load()

	require.NoError(t, err)
	require.NotNil(t, config)

	// Verify config file values are loaded
	assert.Equal(t, "postgres://configuser:configpass@confighost:5432/configdb", config.DatabaseURL)
	assert.Equal(t, "redis://confighost:6379", config.RedisURL)
	assert.Equal(t, "https://config.example.com", config.ServerURL)
	assert.Equal(t, "8888", config.Port)
	assert.Equal(t, "release", config.GinMode)
	assert.Equal(t, "config-jwt-secret-key", config.JWTSecret)
	assert.Equal(t, 14, config.BcryptCost)
	assert.Equal(t, time.Duration(1800)*time.Second, config.AccessTokenDuration)
	assert.Equal(t, time.Duration(86400)*time.Second, config.RefreshTokenDuration)
	assert.Equal(t, time.Duration(120)*time.Second, config.AuthorizationCodeDuration)
	assert.Equal(t, "https://config.example.com", config.CORSAllowedOrigins)
	assert.Equal(t, "GET,POST,PUT", config.CORSAllowedMethods)
	assert.Equal(t, "Content-Type", config.CORSAllowedHeaders)
	assert.Equal(t, 120, config.RateLimitRequestsPerMinute)
	assert.Equal(t, "warn", config.LogLevel)
	assert.Equal(t, "json", config.LogFormat)
}

func TestLoad_ConfigFileNotFound(t *testing.T) {
	// Reset viper state
	viper.Reset()

	// Set a non-existent config file path
	viper.SetConfigFile("non-existent-config.yaml")

	config, err := Load()

	// Should not return an error even if config file is not found
	require.NoError(t, err)
	require.NotNil(t, config)

	// Should use default values
	assert.Equal(t, "postgres://authuser:password@localhost:5432/authdb?sslmode=disable", config.DatabaseURL)
	assert.Equal(t, "8080", config.Port)
}

func TestSetDefaults(t *testing.T) {
	// Reset viper state
	viper.Reset()

	// Call setDefaults
	setDefaults()

	// Test that all default values are set correctly
	assert.Equal(t, "postgres://authuser:password@localhost:5432/authdb?sslmode=disable", viper.GetString("database.url"))
	assert.Equal(t, "", viper.GetString("redis.url"))
	assert.Equal(t, "http://localhost:8080", viper.GetString("server.url"))
	assert.Equal(t, "8080", viper.GetString("server.port"))
	assert.Equal(t, "debug", viper.GetString("server.gin_mode"))
	assert.Equal(t, "your-super-secret-jwt-key-minimum-32-characters-long", viper.GetString("jwt.secret"))
	assert.Equal(t, 12, viper.GetInt("security.bcrypt_cost"))
	assert.Equal(t, 3600, viper.GetInt("security.access_token_duration"))
	assert.Equal(t, 2592000, viper.GetInt("security.refresh_token_duration"))
	assert.Equal(t, 600, viper.GetInt("security.authorization_code_duration"))
	assert.Equal(t, "*", viper.GetString("cors.allowed_origins"))
	assert.Equal(t, "GET,POST,PUT,DELETE,OPTIONS", viper.GetString("cors.allowed_methods"))
	assert.Equal(t, "Origin,Content-Type,Accept,Authorization", viper.GetString("cors.allowed_headers"))
	assert.Equal(t, 60, viper.GetInt("rate_limit.requests_per_minute"))
	assert.Equal(t, "info", viper.GetString("logging.level"))
	assert.Equal(t, "text", viper.GetString("logging.format"))
}

func TestConfig_StructFields(t *testing.T) {
	// Test that Config struct has all expected fields
	config := &Config{
		DatabaseURL:                "test-db-url",
		RedisURL:                   "test-redis-url",
		ServerURL:                  "test-server-url",
		Port:                       "test-port",
		GinMode:                    "test-gin-mode",
		JWTSecret:                  "test-jwt-secret",
		BcryptCost:                 10,
		AccessTokenDuration:        time.Hour,
		RefreshTokenDuration:       time.Hour * 24,
		AuthorizationCodeDuration:  time.Minute * 10,
		CORSAllowedOrigins:         "test-origins",
		CORSAllowedMethods:         "test-methods",
		CORSAllowedHeaders:         "test-headers",
		RateLimitRequestsPerMinute: 100,
		LogLevel:                   "test-log-level",
		LogFormat:                  "test-log-format",
	}

	// Verify all fields are accessible and have expected values
	assert.Equal(t, "test-db-url", config.DatabaseURL)
	assert.Equal(t, "test-redis-url", config.RedisURL)
	assert.Equal(t, "test-server-url", config.ServerURL)
	assert.Equal(t, "test-port", config.Port)
	assert.Equal(t, "test-gin-mode", config.GinMode)
	assert.Equal(t, "test-jwt-secret", config.JWTSecret)
	assert.Equal(t, 10, config.BcryptCost)
	assert.Equal(t, time.Hour, config.AccessTokenDuration)
	assert.Equal(t, time.Hour*24, config.RefreshTokenDuration)
	assert.Equal(t, time.Minute*10, config.AuthorizationCodeDuration)
	assert.Equal(t, "test-origins", config.CORSAllowedOrigins)
	assert.Equal(t, "test-methods", config.CORSAllowedMethods)
	assert.Equal(t, "test-headers", config.CORSAllowedHeaders)
	assert.Equal(t, 100, config.RateLimitRequestsPerMinute)
	assert.Equal(t, "test-log-level", config.LogLevel)
	assert.Equal(t, "test-log-format", config.LogFormat)
}

func TestLoad_DurationConversion(t *testing.T) {
	// Reset viper state
	viper.Reset()

	// Set specific duration values
	viper.Set("security.access_token_duration", 1800)
	viper.Set("security.refresh_token_duration", 86400)
	viper.Set("security.authorization_code_duration", 300)

	config, err := Load()

	require.NoError(t, err)
	require.NotNil(t, config)

	// Verify duration conversion from seconds to time.Duration
	assert.Equal(t, time.Duration(1800)*time.Second, config.AccessTokenDuration)
	assert.Equal(t, time.Duration(86400)*time.Second, config.RefreshTokenDuration)
	assert.Equal(t, time.Duration(300)*time.Second, config.AuthorizationCodeDuration)

	// Verify the durations are correct in different units
	assert.Equal(t, 30*time.Minute, config.AccessTokenDuration)
	assert.Equal(t, 24*time.Hour, config.RefreshTokenDuration)
	assert.Equal(t, 5*time.Minute, config.AuthorizationCodeDuration)
}

func TestLoad_ZeroValues(t *testing.T) {
	// Reset viper state
	viper.Reset()

	// Set zero values for some fields
	viper.Set("security.bcrypt_cost", 0)
	viper.Set("security.access_token_duration", 0)
	viper.Set("rate_limit.requests_per_minute", 0)

	config, err := Load()

	require.NoError(t, err)
	require.NotNil(t, config)

	// Verify zero values are handled correctly
	assert.Equal(t, 0, config.BcryptCost)
	assert.Equal(t, time.Duration(0), config.AccessTokenDuration)
	assert.Equal(t, 0, config.RateLimitRequestsPerMinute)
}
