// Package config provides configuration loading and management for the identity service.
// It handles environment variable parsing and provides default values for all settings.
package config

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
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
	
	// New fields for enhanced validation
	IssuerURL        string   // ID_ISSUER_URL - Service issuer URL
	AllowedAudiences []string // ID_ALLOWED_AUDIENCES - List of allowed audiences
	DIDMethod        string   // ID_DID_METHOD - DID method (must be "plc" for Phase 1)
	Port             int      // PORT - Server port number
}

// Default configuration values used when environment variables are not set
const (
	defaultAddress        = ":8080"               // Default HTTP server port
	defaultMetricsAddress = ":9090"               // Default metrics server port
	defaultAudience       = "registryaccord-local"  // Default JWT audience
	defaultIssuer         = "registryaccord-identity" // Default JWT issuer
	defaultSessionTTL     = 10 * time.Minute        // Default session token lifetime
	defaultNonceTTL       = 5 * time.Minute         // Default nonce lifetime
	defaultDIDMethod      = "plc"                   // Default DID method for Phase 1
	defaultPort           = 8080                    // Default server port
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

	// Handle ID_ISSUER_URL (new required field)
	issuerURL, exists := os.LookupEnv("ID_ISSUER_URL")
	if !exists {
		return Config{}, errors.New("ID_ISSUER_URL is required")
	}
	// Validate URL format
	if _, err := url.ParseRequestURI(issuerURL); err != nil {
		return Config{}, fmt.Errorf("invalid ID_ISSUER_URL format: %w", err)
	}
	cfg.IssuerURL = issuerURL

	// Handle ID_ALLOWED_AUDIENCES (new required field)
	audiences, exists := os.LookupEnv("ID_ALLOWED_AUDIENCES")
	if !exists {
		return Config{}, errors.New("ID_ALLOWED_AUDIENCES is required")
	}
	// Parse as CSV or JSON
	parsedAudiences, err := parseAudiences(audiences)
	if err != nil {
		return Config{}, fmt.Errorf("invalid ID_ALLOWED_AUDIENCES: %w", err)
	}
	cfg.AllowedAudiences = parsedAudiences

	// Handle ID_DID_METHOD (new field with default)
	method, exists := os.LookupEnv("ID_DID_METHOD")
	if !exists {
		cfg.DIDMethod = defaultDIDMethod // Default to plc for Phase 1
	} else {
		if method != "plc" {
			return Config{}, errors.New("ID_DID_METHOD must be \"plc\" for Phase 1")
		}
		cfg.DIDMethod = method
	}

	// Handle PORT (new field with default)
	portStr, exists := os.LookupEnv("PORT")
	if !exists {
		cfg.Port = defaultPort // Default port
	} else {
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return Config{}, fmt.Errorf("invalid PORT: %w", err)
		}
		if port < 1 || port > 65535 {
			return Config{}, errors.New("PORT must be between 1 and 65535")
		}
		cfg.Port = port
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

// parseAudiences parses a string as either CSV or JSON array of audiences
func parseAudiences(raw string) ([]string, error) {
	// Try to parse as JSON array first
	var jsonAudiences []string
	if err := json.Unmarshal([]byte(raw), &jsonAudiences); err == nil {
		// Validate that we got a non-empty array
		if len(jsonAudiences) == 0 {
			return nil, errors.New("ID_ALLOWED_AUDIENCES must contain at least one audience when in JSON format")
		}
		return jsonAudiences, nil
	}
	
	// If not JSON, parse as CSV
	if raw == "" {
		return nil, errors.New("ID_ALLOWED_AUDIENCES cannot be empty")
	}
	
	// Split by comma and trim whitespace
	audiences := strings.Split(raw, ",")
	for i, audience := range audiences {
		audiences[i] = strings.TrimSpace(audience)
		if audiences[i] == "" {
			return nil, errors.New("ID_ALLOWED_AUDIENCES contains empty audience")
		}
	}
	
	return audiences, nil
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
