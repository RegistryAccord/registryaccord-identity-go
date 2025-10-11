// Package server contains HTTP handlers for the identity service.
// This file implements the readiness check endpoint.
package server

import (
	"context"
	"net/http"
	"time"
)

// readyHandler returns 200 OK if the service is ready to serve requests.
// This endpoint is used by load balancers and orchestration systems
// to determine when the service is healthy and ready to receive traffic.
// 
// Readiness checks:
// 1. Database connectivity (if using PostgreSQL storage)
// 
// Returns 200 OK if all checks pass, 503 Service Unavailable if any check fails.
func (h *Handler) readyHandler(w http.ResponseWriter, r *http.Request) {
	// Create a context with timeout to prevent hanging readiness checks
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Check database connectivity if using a store with database access
	// This uses type assertion to check if the store has a DB() method
	// and if that DB has a PingContext method
	if db, ok := h.store.(interface {
		DB() interface {
			PingContext(ctx context.Context) error
		}
	}); ok {
		// Ping the database to verify connectivity
		// Returns error if database is unreachable or unresponsive
		if err := db.DB().PingContext(ctx); err != nil {
			h.writeError(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "database not ready", correlationIDFrom(r.Context()), nil)
			return
		}
	}

	// All readiness checks passed, service is ready to serve requests
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}
