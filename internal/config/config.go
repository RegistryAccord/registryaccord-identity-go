// Package config provides configuration loading and management for the identity service.
// It handles environment variable parsing and provides default values for all settings.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

// init loads environment variables from .env files during package initialization.
// In development, it loads .env and .env.local files if they exist.
// In production, it relies solely on system environment variables.
// The loading order ensures that system environment variables take precedence over .env files.
func init() {
	// In dev, load .env files if they exist; in production, rely only on environment variables
	// godotenv.Load() does not override already-set environment variables,
	// preserving OS env > .env precedence

	// Load .env file if it exists (for shared development config)
	if _, err := os.Stat(".env"); err == nil {
		if err := godotenv.Load(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to load .env file: %v\n", err)
		}
	}

	// Load .env.local if it exists (for local overrides, gitignored)
	if _, err := os.Stat(".env.local"); err == nil {
		if err := godotenv.Load(".env.local"); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to load .env.local file: %v\n", err)
		}
	}
}

// Config captures environment-driven settings for the identity service.
// It contains all configuration parameters needed to run the identity service.
type Config struct {
	Env             string        // Deployment environment (dev, staging, prod)
	Address         string        // HTTP server address (e.g., ":8080")
	MetricsAddress  string        // Metrics server address (e.g., ":9090")
	DatabaseDSN     string        // Database connection string (PostgreSQL)
	KeyBackend      string        // Key storage backend (memory, postgres)
	FeatureRecovery bool          // Whether identity recovery feature is enabled
	JWTPrivateKey   []byte        // Private key used to sign JWT tokens
	JWTAudience     string        // Expected audience for issued JWTs
	JWTIssuer       string        // Issuer identifier for JWTs
	SessionTTL      time.Duration // Duration before session tokens expire
	NonceTTL        time.Duration // Duration before nonces expire
}

// Default configuration values used when environment variables are not set
const (
	defaultAddress        = ":8080"               // Default HTTP server port
	defaultMetricsAddress = ":9090"               // Default metrics server port
	defaultAudience       = "registryaccord-local"  // Default JWT audience
	defaultIssuer         = "registryaccord-identity" // Default JWT issuer
	defaultSessionTTL     = 10 * time.Minute        // Default session token lifetime
	defaultNonceTTL       = 5 * time.Minute         // Default nonce lifetime
)

// Load reads environment variables and produces a Config suitable for wiring the service.
// It handles both required and optional configuration parameters, providing defaults where appropriate.
// Returns an error if required parameters are missing or invalid.
func Load() (Config, error) {
	cfg := Config{}

	// Handle required environment variables
	env, exists := os.LookupEnv("ID_ENV")
	if !exists {
		cfg.Env = "dev" // Default to dev for local development
	} else {
		cfg.Env = env
	}

	address, exists := os.LookupEnv("ID_HTTP_ADDR")
	if !exists {
		cfg.Address = defaultAddress
	} else {
		cfg.Address = address
	}

	metricsAddr, exists := os.LookupEnv("ID_METRICS_ADDR")
	if !exists {
		cfg.MetricsAddress = defaultMetricsAddress
	} else {
		cfg.MetricsAddress = metricsAddr
	}

	jwtAud, exists := os.LookupEnv("ID_JWT_AUD")
	if !exists {
		cfg.JWTAudience = defaultAudience
	} else {
		cfg.JWTAudience = jwtAud
	}

	jwtIss, exists := os.LookupEnv("ID_JWT_ISS")
	if !exists {
		cfg.JWTIssuer = defaultIssuer
	} else {
		cfg.JWTIssuer = jwtIss
	}

	// Handle optional variables
	if backend, exists := os.LookupEnv("ID_KEY_BACKEND"); exists {
		cfg.KeyBackend = strings.ToLower(backend)
	} else {
		cfg.KeyBackend = "memory" // Default to memory backend
	}

	if recovery, exists := os.LookupEnv("ID_FEATURE_RECOVERY"); exists {
		cfg.FeatureRecovery = parseBool(recovery)
	} else {
		cfg.FeatureRecovery = false // Default to false for security
	}

	if dsn, exists := os.LookupEnv("ID_DB_DSN"); exists {
		cfg.DatabaseDSN = dsn
	}

	if ttl, exists := os.LookupEnv("ID_SESSION_TTL_SECONDS"); exists {
		d, err := parseSeconds(ttl)
		if err != nil {
			return Config{}, fmt.Errorf("invalid ID_SESSION_TTL_SECONDS: %w", err)
		}
		cfg.SessionTTL = d
	} else {
		cfg.SessionTTL = defaultSessionTTL
	}

	if ttl, exists := os.LookupEnv("ID_NONCE_TTL_SECONDS"); exists {
		d, err := parseSeconds(ttl)
		if err != nil {
			return Config{}, fmt.Errorf("invalid ID_NONCE_TTL_SECONDS: %w", err)
		}
		cfg.NonceTTL = d
	} else {
		cfg.NonceTTL = defaultNonceTTL
	}

	// Handle required JWT signing key
	signingKey, exists := os.LookupEnv("ID_JWT_SIGNING_KEY")
	if !exists {
		return Config{}, errors.New("ID_JWT_SIGNING_KEY is required")
	}
	keyBytes, err := base64.StdEncoding.DecodeString(signingKey)
	if err != nil {
		return Config{}, fmt.Errorf("invalid ID_JWT_SIGNING_KEY base64: %w", err)
	}
	cfg.JWTPrivateKey = keyBytes

	return cfg, nil
}

// getEnv retrieves an environment variable value, returning a fallback if not set or empty
func getEnv(key, fallback string) string {
	if v, exists := os.LookupEnv(key); exists && v != "" {
		return v
	}
	return fallback
}

// parseBool converts a string to a boolean value, returning false if parsing fails
func parseBool(v string) bool {
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false
	}
	return b
}

// parseSeconds converts a string representation of seconds to a time.Duration
// Returns an error if the value is not a valid positive integer
func parseSeconds(raw string) (time.Duration, error) {
	seconds, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, err
	}
	if seconds <= 0 {
		return 0, errors.New("value must be > 0")
	}
	return time.Duration(seconds) * time.Second, nil
}
