package config

import (
	"os"
	"strconv"
	"time"
)

// Config holds all application configuration
type Config struct {
	// Server
	ServerPort string
	ServerHost string

	// Database
	DBHost     string
	DBPort     int
	DBUser     string
	DBPassword string
	DBName     string
	DBSSLMode  string

	// JWT
	JWTSecret          string
	JWTExpiration      time.Duration
	RefreshTokenExpiry time.Duration

	// Encryption
	EncryptionKey string // 32 bytes for AES-256

	// Security
	AllowedOrigins []string
	RateLimit      int // requests per minute

	// Audit
	AuditRetentionDays int

	// Environment
	Environment string // development, staging, production
}

// Load loads configuration from environment variables
func Load() *Config {
	return &Config{
		// Server - default to 0.0.0.0:8080 for container compatibility
		ServerPort: getEnv("SERVER_PORT", "8080"),
		ServerHost: getEnv("SERVER_HOST", "0.0.0.0"),

		// Database - defaults for Docker
		DBHost:     getEnv("DB_HOST", "localhost"),
		DBPort:     getEnvAsInt("DB_PORT", 5432),
		DBUser:     getEnv("DB_USER", "medical_user"),
		DBPassword: getEnv("DB_PASSWORD", "secure_password"),
		DBName:     getEnv("DB_NAME", "medical_records"),
		DBSSLMode:  getEnv("DB_SSL_MODE", "require"),

		// JWT - MUST be changed in production!
		JWTSecret:          getEnv("JWT_SECRET", "CHANGE_ME_IN_PRODUCTION_32_CHARACTERS_MIN"),
		JWTExpiration:      getEnvAsDuration("JWT_EXPIRATION", 15*time.Minute),
		RefreshTokenExpiry: getEnvAsDuration("REFRESH_TOKEN_EXPIRY", 24*7*time.Hour),

		// Encryption - MUST be 32 bytes hex-encoded for AES-256
		EncryptionKey: getEnv("ENCRYPTION_KEY", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),

		// Security
		AllowedOrigins: getEnvAsSlice("ALLOWED_ORIGINS", ","),
		RateLimit:      getEnvAsInt("RATE_LIMIT", 100),

		// Audit - HIPAA requires minimum 6 years retention
		AuditRetentionDays: getEnvAsInt("AUDIT_RETENTION_DAYS", 2190), // 6 years

		// Environment
		Environment: getEnv("ENVIRONMENT", "development"),
	}
}

// getEnv retrieves the value of the environment variable or returns the default
func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

// getEnvAsInt retrieves the value of the environment variable as an int or returns the default
func getEnvAsInt(key string, defaultValue int) int {
	if value, exists := os.LookupEnv(key); exists {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return defaultValue
}

// getEnvAsDuration retrieves the value of the environment variable as a duration or returns the default
func getEnvAsDuration(key string, defaultValue time.Duration) time.Duration {
	if value, exists := os.LookupEnv(key); exists {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}

// getEnvAsSlice retrieves the value of the environment variable as a slice or returns the default
func getEnvAsSlice(key, separator string) []string {
	if value, exists := os.LookupEnv(key); exists && value != "" {
		return splitAndTrim(value, separator)
	}
	return []string{}
}

// splitAndTrim splits a string by separator and trims whitespace from each element
func splitAndTrim(s, sep string) []string {
	parts := make([]string, 0)
	for _, part := range split(s, sep) {
		if trimmed := trim(part); trimmed != "" {
			parts = append(parts, trimmed)
		}
	}
	return parts
}

func split(s, sep string) []string {
	if s == "" {
		return nil
	}
	var result []string
	start := 0
	for i := 0; i < len(s); i++ {
		if i+len(sep) <= len(s) && s[i:i+len(sep)] == sep {
			result = append(result, s[start:i])
			start = i + len(sep)
			i += len(sep) - 1
		}
	}
	result = append(result, s[start:])
	return result
}

func trim(s string) string {
	start, end := 0, len(s)-1
	for start <= end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
		start++
	}
	for end >= start && (s[end] == ' ' || s[end] == '\t' || s[end] == '\n' || s[end] == '\r') {
		end--
	}
	if start > end {
		return ""
	}
	return s[start : end+1]
}

// IsProduction returns true if the environment is production
func (c *Config) IsProduction() bool {
	return c.Environment == "production"
}

// IsDevelopment returns true if the environment is development
func (c *Config) IsDevelopment() bool {
	return c.Environment == "development"
}

// DSN returns the PostgreSQL connection string
func (c *Config) DSN() string {
	return "host=" + c.DBHost +
		" port=" + strconv.Itoa(c.DBPort) +
		" user=" + c.DBUser +
		" password=" + c.DBPassword +
		" dbname=" + c.DBName +
		" sslmode=" + c.DBSSLMode
}
