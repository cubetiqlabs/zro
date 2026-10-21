# syntax=docker/dockerfile:1.4
# Stage 1: Statically compiled Go builder
FROM golang:1.27-alpine AS builder

WORKDIR /src

# Install git and ca-certificates
RUN apk add --no-cache git ca-certificates

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source tree
COPY . .

# Build statically linked binary without CGO, stamped with the build version
ARG VERSION=dev
ARG COMMIT=
ARG DATE=
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -extldflags '-static' -X github.com/cubis/zro/pkg/version.Version=${VERSION} -X github.com/cubis/zro/pkg/version.Commit=${COMMIT} -X github.com/cubis/zro/pkg/version.Date=${DATE}" \
    -trimpath \
    -o /bin/zro \
    ./cmd/zro

# Stage 2: Production minimal runtime
FROM alpine:3.23

# Runtime utilities: `ip` programs overlay addresses/routes, curl serves health checks.
# (No iptables: ZRO relies on WireGuard AllowedIPs and kernel routing, not NAT rules.)
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
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
