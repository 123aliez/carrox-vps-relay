# syntax=docker/dockerfile:1.6
# ---- Stage 1: build the Go binary ----
FROM golang:1.22-alpine AS builder

ENV CGO_ENABLED=0 \
    GO111MODULE=on

WORKDIR /src

# Cache deps first
COPY go.mod ./
# go.sum may not exist yet for skeleton; suppress error
RUN if [ -f go.sum ]; then cp go.sum ./; fi
RUN go mod download || true

# Copy source
COPY . .

RUN go build -ldflags="-s -w" -o /out/vps-relay .

# ---- Stage 2: runtime ----
FROM alpine:3.20

ARG ACME_EMAIL=bootstrap@vps-relay.local

RUN apk add --no-cache \
        bash \
        curl \
        openssl \
        ca-certificates \
        bind-tools \
        jq \
        tzdata \
        socat \
        nginx \
        nginx-mod-stream \
        shadow \
    && (getent group www >/dev/null || addgroup -S www) \
    && (id www >/dev/null 2>&1 || adduser -SDH -G www -s /sbin/nologin www) \
    && curl -fsSL https://get.acme.sh | sh -s "email=${ACME_EMAIL}" \
    && ln -sf /root/.acme.sh/acme.sh /usr/local/bin/acme.sh

# Binary + helpers
COPY --from=builder /out/vps-relay /usr/local/bin/vps-relay
COPY scripts/relay-acme.sh         /usr/local/bin/relay-acme

# Static + templates
COPY templates/ /opt/vps-relay/templates/
COPY web/       /opt/vps-relay/web/

RUN chmod +x /usr/local/bin/vps-relay /usr/local/bin/relay-acme

EXPOSE 8787

# Health endpoint is wired in main.go from M2 onward
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8787/api/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/vps-relay"]
