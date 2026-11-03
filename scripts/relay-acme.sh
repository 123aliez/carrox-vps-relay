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
#   - 重载：通过 vps-relay 同步派生配置、检查语法后发送 SIGHUP。
#                  (host nginx binary is glibc-linked and can't be exec'd from
#                   our alpine container; signaling works because the container
#                   shares host PID namespace + has CAP_KILL.)
set -euo pipefail

# 所有分支先由 Go 取得或验证真实配置锁，检查迁移后再执行整个脚本正文。
# 通过标准输入传递正文，不提供可被参数或环境变量绕过的“已加锁”分支。
exec vps-relay lock-run -- vps-relay acme-transaction "${1:?usage: relay-acme <domain> [issue|renew|remove]}" "${2:-issue}" -- /bin/bash -s -- "$@" <<'RELAY_ACME_LOCKED'
set -euo pipefail

DOMAIN="${1:?usage: relay-acme <domain> [issue|renew|revoke]}"
ACTION="${2:-issue}"

: "${CF_API_TOKEN:?CF_API_TOKEN env required for DNS-01 with Cloudflare}"
export CF_Token="$CF_API_TOKEN"   # acme.sh expects this variable name for dns_cf

SSL_DIR="${VPS_RELAY_CERT_STAGE:?证书事务暂存目录缺失}"
ACME_HOME="${ACME_HOME:-/root/.acme.sh}"
ACME="$ACME_HOME/acme.sh"
# 隔离阶段不触碰运行中的 Nginx；Go 校验证书对并发布后保存真实重载命令。
RELOAD_CMD=':'

case "$ACTION" in
  issue)
    "$ACME" --home "$ACME_HOME" --set-default-ca --server letsencrypt >/dev/null 2>&1
    "$ACME" --home "$ACME_HOME" --issue --dns dns_cf -d "$DOMAIN" --keylength ec-256
    install -d "$SSL_DIR"
    "$ACME" --home "$ACME_HOME" --install-cert -d "$DOMAIN" --ecc \
      --fullchain-file "$SSL_DIR/fullchain.pem" \
      --key-file       "$SSL_DIR/key.pem" \
      --reloadcmd      "$RELOAD_CMD"
    ;;
  renew)
    # 更新旧证书保存的重载命令，避免历史配置绕过派生文件同步。
    "$ACME" --home "$ACME_HOME" --install-cert -d "$DOMAIN" --ecc \
      --fullchain-file "$SSL_DIR/fullchain.pem" \
      --key-file "$SSL_DIR/key.pem" \
      --reloadcmd "$RELOAD_CMD"
    "$ACME" --home "$ACME_HOME" --renew -d "$DOMAIN" --ecc --force
    ;;
  remove)
    "$ACME" --home "$ACME_HOME" --remove -d "$DOMAIN" --ecc
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

RELAY_ACME_LOCKED
