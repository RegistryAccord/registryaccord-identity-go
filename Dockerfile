# Build stage
FROM golang:1.25-alpine AS builder

# Install ca-certificates for HTTPS requests
RUN apk add --no-cache ca-certificates

# Create non-root user
RUN adduser -D -s /bin/sh registryaccord

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o bin/identityd ./cmd/identityd

# Final stage
FROM scratch

# Copy certificates
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy user
COPY --from=builder /etc/passwd /etc/passwd

# Copy binary
COPY --from=builder /app/bin/identityd /identityd

# Use non-root user
USER registryaccord

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --quiet --tries=1 --spider http://localhost:8080/health || exit 1

# Run binary
ENTRYPOINT ["/identityd"]
