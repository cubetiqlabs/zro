# syntax=docker/dockerfile:1.4
# Stage 1: Statically compiled Go builder
FROM golang:alpine AS builder

WORKDIR /src

# Install git and ca-certificates
RUN apk add --no-cache git ca-certificates

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source tree
COPY . .

# Build statically linked binary without CGO
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -extldflags '-static'" \
    -trimpath \
    -o /bin/zro \
    ./cmd/zro

# Stage 2: Production minimal runtime
FROM alpine:3.21

# Install runtime utilities for network interfaces & SSL
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    iptables \
    iproute2 \
    curl

# Copy compiled binary from builder
COPY --from=builder /bin/zro /usr/local/bin/zro

# Default directories for configs and certs
RUN mkdir -p /etc/zro /var/lib/zro/certs

WORKDIR /

# Standard ports:
# 8443: Control Plane API
# 51820/udp: WireGuard / STUN Edge Listener
# 80 / 443: Ingress Gateway HTTP / HTTPS
EXPOSE 8443 51820/udp 80 443

ENTRYPOINT ["/usr/local/bin/zro"]
CMD ["--help"]
