// Package server contains HTTP handlers and middleware for the identity service.
// This file implements middleware functions for timeout handling, logging, and metrics collection.
package server

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Prometheus metrics for monitoring HTTP requests
var (
	// Counter for total HTTP requests by method, path, and status code
	requestCount = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests made.",
		},
		[]string{"method", "path", "code"},
	)

	// Histogram for HTTP request duration by method and path
	requestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "HTTP request duration in seconds.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "path"},
	)
)

// timeoutMiddleware adds a timeout to requests to prevent resource exhaustion.
// Sets a 30-second timeout for all HTTP requests to ensure responsiveness.
// Uses context.WithTimeout to propagate the timeout to downstream operations.
func (h *Handler) timeoutMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Create a context with 30-second timeout
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		// Ensure the context is cancelled to free resources
		defer cancel()
		// Pass the request with timeout context to the next handler
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// loggingMiddleware logs request details and collects metrics for monitoring.
// Records request method, path, status code, duration, and user agent.
// Collects Prometheus metrics for request count and duration.
func (h *Handler) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Record start time for duration calculation
		start := time.Now()

		// Wrap ResponseWriter to capture the actual status code returned
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		// Process the request through the next handler in the chain
		next.ServeHTTP(wrapped, r)

		// Calculate request duration
		duration := time.Since(start)

		// Log request details for operational visibility
		h.logger.Info("request completed",
			"method", r.Method,           // HTTP method (GET, POST, etc.)
			"path", r.URL.Path,           // Request path
			"status", wrapped.statusCode, // Actual HTTP status code returned
			"duration", duration,         // Request processing time
			"user_agent", r.UserAgent(),  // Client user agent string
		)

		// Collect metrics for monitoring and alerting
		// Normalize empty path to root path for consistent labeling
		path := r.URL.Path
		if path == "" {
			path = "/"
		}

		// Increment request counter with labels for filtering
		requestCount.WithLabelValues(r.Method, path, strconv.Itoa(wrapped.statusCode)).Inc()
		// Record request duration in histogram for latency analysis
		requestDuration.WithLabelValues(r.Method, path).Observe(duration.Seconds())
	})
}

// responseWriter wraps http.ResponseWriter to capture the HTTP status code.
// This allows the logging middleware to record the actual status code returned by handlers.
// Implements the http.ResponseWriter interface by embedding the original ResponseWriter.
type responseWriter struct {
	http.ResponseWriter // Embedded original ResponseWriter
	statusCode int       // Captured HTTP status code
}

// WriteHeader captures the status code before calling the original WriteHeader.
// This ensures we can log the actual status code returned by handlers.
func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code                     // Capture the status code
	rw.ResponseWriter.WriteHeader(code)      // Call original WriteHeader
}

// Write delegates to the original ResponseWriter's Write method.
// This is needed to fully implement the http.ResponseWriter interface.
func (rw *responseWriter) Write(b []byte) (int, error) {
	return rw.ResponseWriter.Write(b)        // Delegate to original Write
}
