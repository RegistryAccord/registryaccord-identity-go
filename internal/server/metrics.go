// Package server contains HTTP handlers for the identity service.
// This file implements Prometheus metrics exposure endpoints.
package server

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// metricsHandler exposes Prometheus metrics through the main HTTP server.
// This endpoint serves metrics in the Prometheus exposition format
// for monitoring and alerting purposes.
// 
// The metrics include:
// - HTTP request count and duration (from middleware)
// - Go runtime metrics (automatically collected by Prometheus client)
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
