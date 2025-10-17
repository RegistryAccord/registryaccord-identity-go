// Package server contains HTTP handlers and middleware for the identity service.
// This file implements CORS middleware for handling Cross-Origin Resource Sharing.
package server

import (
	"net/http"
)

// corsMiddleware adds CORS headers to responses to enable cross-origin requests.
// This middleware handles both simple and preflight CORS requests.
// In production, it should be configured with specific allowed origins.
func (h *Handler) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		// In production, these should be restricted to specific origins
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Correlation-Id, Idempotency-Key")
		w.Header().Set("Access-Control-Max-Age", "86400") // 24 hours
		
		// Handle preflight OPTIONS requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		
		// Continue with the next handler
		next.ServeHTTP(w, r)
	})
}
