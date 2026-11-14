#!/usr/bin/env bash
# install.sh — one-shot bring-up helper for vps-relay on a host that already has
# Nginx 1.28.x and Docker installed.
#
# What it does (idempotent):
#   1. Verifies host prerequisites (nginx 1.28 + required modules, docker)
#   2. Ensures /usr/local/nginx/conf/nginx.conf contains `connection_upgrade` map
#      (fallback: auto-patch only if missing; keeps a timestamped .bak)
#   3. Creates /etc/vps-relay/ directory
#   4. Optionally adds a panel vhost when `--domain` is provided
#   5. Builds the image and runs `docker compose up -d`
#   6. Outputs deployment info (admin key is auto-generated on first start)
#
# Re-run safe.
set -euo pipefail

log() { printf '[install] %s\n' "$*"; }

PANEL_DOMAIN=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --domain)
      if [ "$#" -lt 2 ] || [ -z "${2:-}" ]; then
        echo "ERROR: --domain requires a value." >&2
        exit 1
      fi
      PANEL_DOMAIN="$2"
      shift 2
      ;;
    *)
      echo "ERROR: unknown argument: $1" >&2
      echo "usage: bash deploy/install.sh [--domain panel.example.com]" >&2
      exit 1
      ;;
  esac
done

HERE="$(cd "$(dirname "$0")/.." && pwd)"
NGX_CONF=/usr/local/nginx/conf/nginx.conf

require_nginx_feature() {
  local name="$1"
  local pattern="$2"
  local output="$3"
  if ! printf '%s\n' "$output" | grep -Eq -- "$pattern"; then
    echo "ERROR: nginx is missing required feature: $name" >&2
    exit 1
  fi
}

ensure_connection_upgrade_map() {
  if grep -qE 'connection_upgrade' "$NGX_CONF"; then
    log "connection_upgrade map already present"
    return 0
  fi

  log "patching nginx.conf with connection_upgrade map (fallback)"
  local backup="${NGX_CONF}.bak.$(date +%Y%m%d%H%M%S)"
  cp "$NGX_CONF" "$backup"
  python3 "$HERE/deploy/patch-nginx-map.py" "$NGX_CONF"

  if /usr/local/nginx/sbin/nginx -p /usr/local/nginx -c conf/nginx.conf -t >/dev/null 2>&1; then
    /usr/local/nginx/sbin/nginx -s reload
  else
    cp "$backup" "$NGX_CONF"
    echo "ERROR: nginx -t failed after fallback patch attempt; original restored from $backup." >&2
    exit 1
  fi
}

ensure_stream_block() {
  install -d -m 0755 /usr/local/nginx/conf/stream.d
  if grep -qE '^[[:space:]]*include[[:space:]]+[^[:space:]]*stream\.d/\*\.conf[[:space:]]*;' "$NGX_CONF"; then
    log "stream block already present"
    return 0
  fi

  log "patching nginx.conf with stream block (TCP forwards)"
  local backup="${NGX_CONF}.bak.$(date +%Y%m%d%H%M%S)"
  cp "$NGX_CONF" "$backup"
  if ! python3 "$HERE/deploy/patch-nginx-stream.py" "$NGX_CONF"; then
    cp "$backup" "$NGX_CONF"
    echo "ERROR: stream patch failed; original restored from $backup." >&2
    exit 1
  fi
  if ! /usr/local/nginx/sbin/nginx -p /usr/local/nginx -c conf/nginx.conf -t >/dev/null 2>&1; then
    cp "$backup" "$NGX_CONF"
    echo "ERROR: nginx -t failed after stream patch attempt; original restored from $backup." >&2
    exit 1
  fi
  if ! /usr/local/nginx/sbin/nginx -s reload; then
    cp "$backup" "$NGX_CONF"
    echo "ERROR: nginx reload failed after stream patch attempt; original restored from $backup." >&2
    exit 1
  fi
}

# --- 1. Prereq checks ------------------------------------------------------
if [ ! -x /usr/local/nginx/sbin/nginx ]; then
  echo "ERROR: /usr/local/nginx/sbin/nginx not found — install nginx 1.28.x first." >&2
  exit 1
fi
NGX_VER=$(/usr/local/nginx/sbin/nginx -v 2>&1 | sed 's|.*nginx/||')
log "nginx version: $NGX_VER"

NGX_BUILD_INFO=$(/usr/local/nginx/sbin/nginx -V 2>&1)
require_nginx_feature "http_ssl" '--with-http_ssl_module' "$NGX_BUILD_INFO"
require_nginx_feature "http_v2" '--with-http_v2_module' "$NGX_BUILD_INFO"
require_nginx_feature "http_v3" '--with-http_v3_module' "$NGX_BUILD_INFO"
require_nginx_feature "stream" '--with-stream([[:space:]]|$)' "$NGX_BUILD_INFO"
require_nginx_feature "http_realip" '--with-http_realip_module' "$NGX_BUILD_INFO"

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker not found." >&2
  exit 1
fi
if ! docker info >/dev/null 2>&1; then
  echo "ERROR: docker daemon not running." >&2
  exit 1
fi
if ! docker compose version >/dev/null 2>&1; then
  echo "ERROR: docker compose not available." >&2
  exit 1
fi

# --- 2. nginx.conf fallback patch ------------------------------------------
ensure_connection_upgrade_map
ensure_stream_block

# --- 3. /etc/vps-relay/ ----------------------------------------------------
install -d -m 0750 /etc/vps-relay
install -d -m 0755 /usr/local/nginx/conf/ssl
install -d -m 0755 /usr/local/nginx/conf/conf.d

# --- 4. Optional panel vhost ------------------------------------------------
if [ -n "$PANEL_DOMAIN" ]; then
  PANEL_CONF=/usr/local/nginx/conf/conf.d/relay-panel.conf
  # Only treat it as a conflict when grep actually matches something:
  # `xargs -r grep` returns 0 on empty input without running grep, which
  # falsely flagged a fresh install (empty conf.d) as a domain conflict.
  if [[ -n "$(find /usr/local/nginx/conf/conf.d -maxdepth 1 -type f -name '*.conf' -exec grep -l -E "server_name[[:space:]]+.*\\b${PANEL_DOMAIN//./\\.}\\b" {} + 2>/dev/null)" ]]; then
    if [ ! -f "$PANEL_CONF" ] || ! grep -q "server_name $PANEL_DOMAIN;" "$PANEL_CONF"; then
      echo "ERROR: panel domain already used by another nginx conf: $PANEL_DOMAIN" >&2
      exit 1
    fi
  fi

  # 已签发面板证书时保持 HTTPS，重跑安装不能退回明文。
  PANEL_TMPL="$HERE/templates/panel.conf.tmpl"
  if [ -f "/usr/local/nginx/conf/ssl/$PANEL_DOMAIN/fullchain.pem" ]; then
    PANEL_TMPL="$HERE/templates/panel-ssl.conf.tmpl"
  fi
  bash "$HERE/deploy/render-panel-conf.sh" "$PANEL_DOMAIN" "$PANEL_TMPL" > "${PANEL_CONF}.new"
  # 备份文件名不以 .conf 结尾，避免被 conf.d/*.conf 包含。
  PANEL_BAK="${PANEL_CONF}.bak-install"
  rm -f "$PANEL_BAK"
  if [ -f "$PANEL_CONF" ]; then
    cp -p "$PANEL_CONF" "$PANEL_BAK"
  fi
  mv "${PANEL_CONF}.new" "$PANEL_CONF"
  if /usr/local/nginx/sbin/nginx -p /usr/local/nginx -c conf/nginx.conf -t >/dev/null 2>&1; then
    rm -f "$PANEL_BAK"
    /usr/local/nginx/sbin/nginx -s reload
  else
    if [ -f "$PANEL_BAK" ]; then
      mv "$PANEL_BAK" "$PANEL_CONF"
    else
      rm -f "$PANEL_CONF"
    fi
    echo "ERROR: nginx -t failed for panel conf." >&2
    exit 1
  fi
fi

# --- 5. Build + up ---------------------------------------------------------
cd "$HERE"

log "building image vps-relay:latest"
docker build -t vps-relay:latest .

log "starting docker compose"
docker compose up -d

sleep 3

# --- 6. Output deployment info ---------------------------------------------
for i in $(seq 1 10); do
  if curl -sf http://127.0.0.1:8787/api/healthz >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

ADMIN_KEY=$(docker logs vps-relay 2>&1 | grep -oP '已自动生成管理员密钥：\s*\K\S+' || true)
EDGE_IP=$(curl -sf --max-time 5 https://ifconfig.me 2>/dev/null || echo '<未检测到>')

echo ""
echo "============================================"
echo "  vps-relay 部署完成"
echo "============================================"
echo ""
if [ -n "$PANEL_DOMAIN" ]; then
  echo "  面板地址:   http://$PANEL_DOMAIN"
else
  echo "  面板地址:   http://127.0.0.1:8787"
fi
echo "  边缘 IP:    $EDGE_IP"
echo "  容器状态:   $(docker inspect -f '{{.State.Status}}' vps-relay 2>/dev/null || echo unknown)"
echo "  版本:       $(curl -sf http://127.0.0.1:8787/api/healthz | grep -oP '"version":"\K[^"]+' || echo unknown)"
echo ""

if [ -n "$ADMIN_KEY" ]; then
  echo "  管理员密钥: $ADMIN_KEY"
  echo ""
  echo "  ⚠  请立即登录面板，配置 Cloudflare API Token。"
  echo "  ⚠  可通过面板「密钥管理」为其他用户创建密钥。"
else
  echo "  管理员密钥已在之前生成，请查看 /etc/vps-relay/keys.json"
  echo "  或运行: docker logs vps-relay 2>&1 | grep 密钥"
fi

echo ""
echo "============================================"

DEPLOY_LOG="/etc/vps-relay/deploy-$(date +%Y%m%d%H%M%S).log"
{
  echo "vps-relay deploy info — $(date)"
  echo "edge_ip=$EDGE_IP"
  echo "container=$(docker inspect -f '{{.State.Status}}' vps-relay 2>/dev/null || echo unknown)"
  echo "version=$(curl -sf http://127.0.0.1:8787/api/healthz | grep -oP '"version":"\K[^"]+' || echo unknown)"
  echo "admin_key=${ADMIN_KEY:-<see keys.json or container logs>}"
  echo "panel_domain=${PANEL_DOMAIN:-}"
} > "$DEPLOY_LOG"
chmod 600 "$DEPLOY_LOG"
log "部署信息已保存到 $DEPLOY_LOG"
