// Package server contains HTTP handlers for the identity service.
// This file implements Prometheus metrics exposure endpoints.
package server

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Additional Prometheus metrics for identity service operations
var (
	// Counter for JWKS cache refreshes
	jwksCacheRefreshes = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "jwks_cache_refreshes_total",
			Help: "Total number of JWKS cache refreshes.",
		},
	)

	// Counter for nonce issuance
	nonceIssuanceCount = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "nonce_issuance_total",
			Help: "Total number of nonces issued.",
		},
	)

	// Counter for nonce validation
	nonceValidationCount = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "nonce_validation_total",
			Help: "Total number of nonce validations, by result.",
		},
		[]string{"result"}, // success, expired, invalid, replay
	)

	// Counter for JWT issuance
	jwtIssuanceCount = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "jwt_issuance_total",
			Help: "Total number of JWTs issued.",
		},
	)

	// Counter for key rotations
	keyRotationCount = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "key_rotations_total",
			Help: "Total number of key rotations, by result.",
		},
		[]string{"result"}, // success, failure
	)

	// Counter for identity recoveries
	identityRecoveryCount = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "identity_recoveries_total",
			Help: "Total number of identity recoveries, by result.",
		},
		[]string{"result"}, // success, failure
	)
)

// metricsHandler exposes Prometheus metrics through the main HTTP server.
// This endpoint serves metrics in the Prometheus exposition format
// for monitoring and alerting purposes.
//
// The metrics include:
// - HTTP request count and duration (from middleware)
// - Go runtime metrics (automatically collected by Prometheus client)
// - Identity service specific metrics
func (h *Handler) metricsHandler(w http.ResponseWriter, r *http.Request) {
	// Delegate to the Prometheus HTTP handler which serves metrics
	// in the appropriate format for scraping by Prometheus
	promhttp.Handler().ServeHTTP(w, r)
}

// NewMetricsHandler creates a standalone HTTP handler for Prometheus metrics.
// This is used to create a separate metrics server that can listen on a
// different port, providing operational isolation between application
// traffic and metrics scraping.
func NewMetricsHandler() http.Handler {
	// Return the standard Prometheus handler
	return promhttp.Handler()
}

// incrementJWKSCacheRefreshes increments the JWKS cache refreshes counter
func incrementJWKSCacheRefreshes() {
	jwksCacheRefreshes.Inc()
}

// incrementNonceIssuance increments the nonce issuance counter
func incrementNonceIssuance() {
	nonceIssuanceCount.Inc()
}

// incrementNonceValidation increments the nonce validation counter
func incrementNonceValidation(result string) {
	nonceValidationCount.WithLabelValues(result).Inc()
}

// incrementJWTIssuance increments the JWT issuance counter
func incrementJWTIssuance() {
	jwtIssuanceCount.Inc()
}

// incrementKeyRotation increments the key rotation counter
func incrementKeyRotation(result string) {
	keyRotationCount.WithLabelValues(result).Inc()
}

// incrementIdentityRecovery increments the identity recovery counter
func incrementIdentityRecovery(result string) {
	identityRecoveryCount.WithLabelValues(result).Inc()
}
