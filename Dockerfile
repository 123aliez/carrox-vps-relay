# syntax=docker/dockerfile:1.6
# ---- Stage 1: build the Go binary ----
FROM golang:1.22-alpine AS builder

ENV CGO_ENABLED=0 \
    GO111MODULE=on

# 仅下载固定版本的 Xray 可执行文件，不携带地理数据文件。
RUN apk add --no-cache curl unzip \
    && curl -fL --retry 3 -o /tmp/xray.zip https://github.com/XTLS/Xray-core/releases/download/v26.10.31/Xray-linux-64.zip \
    && echo 'e4bd9119f50ae7c41658b1abd0679ae06f98bd864a2907ff33f2f2cf7081b214  /tmp/xray.zip' | sha256sum -c - \
    && mkdir -p /out \
    && unzip -p /tmp/xray.zip xray > /out/xray \
    && chmod 0755 /out/xray \
    && rm /tmp/xray.zip

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
COPY --from=builder /out/xray /usr/local/bin/xray
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
