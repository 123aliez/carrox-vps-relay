#!/usr/bin/env bash
# relay-acme — acme.sh DNS-01 wrapper for vps-relay
#
# Designed to run *inside* the vps-relay container:
#   docker exec -e CF_API_TOKEN=xxx -e ACME_HOME=/root/.acme.sh-user1 \
#     vps-relay relay-acme <domain> issue|renew|revoke
#
# Aligns with vps-manager/apply_ssl.sh conventions:
#   - certificate install path: /usr/local/nginx/conf/ssl/<domain>/{fullchain.pem,key.pem}
#
# Diverges from apply_ssl.sh in:
#   - validation:  DNS-01 (apply_ssl.sh uses HTTP-01 webroot)
#   - DNS:         driven by Cloudflare API token, no port-80 dependency
#   - reload:      `kill -HUP $(cat /usr/local/nginx/logs/nginx.pid)`
#                  (host nginx binary is glibc-linked and can't be exec'd from
#                   our alpine container; signaling works because the container
#                   shares host PID namespace + has CAP_KILL.)
set -euo pipefail

DOMAIN="${1:?usage: relay-acme <domain> [issue|renew|revoke]}"
ACTION="${2:-issue}"

: "${CF_API_TOKEN:?CF_API_TOKEN env required for DNS-01 with Cloudflare}"
export CF_Token="$CF_API_TOKEN"   # acme.sh expects this variable name for dns_cf

SSL_DIR="/usr/local/nginx/conf/ssl/$DOMAIN"
ACME_HOME="${ACME_HOME:-/root/.acme.sh}"
ACME="$ACME_HOME/acme.sh"
RELOAD_CMD='kill -HUP $(cat /usr/local/nginx/logs/nginx.pid)'

case "$ACTION" in
  issue)
    "$ACME" --home "$ACME_HOME" --set-default-ca --server letsencrypt >/dev/null 2>&1 || true
    "$ACME" --home "$ACME_HOME" --issue --dns dns_cf -d "$DOMAIN" --keylength ec-256
    install -d "$SSL_DIR"
    "$ACME" --home "$ACME_HOME" --install-cert -d "$DOMAIN" --ecc \
      --fullchain-file "$SSL_DIR/fullchain.pem" \
      --key-file       "$SSL_DIR/key.pem" \
      --reloadcmd      "$RELOAD_CMD"
    ;;
  renew)
    "$ACME" --home "$ACME_HOME" --renew -d "$DOMAIN" --ecc --force
    ;;
  remove)
    "$ACME" --home "$ACME_HOME" --remove -d "$DOMAIN" --ecc || true
    # `--remove` only de-registers from the renew list; we also wipe the
    # _ecc material so a subsequent `issue` can re-create the domain key
    # without needing --force.
    rm -rf "$SSL_DIR" "$ACME_HOME/${DOMAIN}_ecc"
    ;;
  *)
    echo "未知操作: $ACTION (应为 issue|renew|remove)" >&2
    exit 2
    ;;
esac
