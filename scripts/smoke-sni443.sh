#!/bin/sh
# 在构建镜像内检查与 Go 渲染一致的 SNI 测试夹具。
set -eu
NGX_PREFIX=/usr/local/nginx
mkdir -p "$NGX_PREFIX/conf/stream.d/relay-443" "$NGX_PREFIX/conf/conf.d" "$NGX_PREFIX/logs" /tmp/ngx
cp /fixtures/nginx.conf "$NGX_PREFIX/conf/nginx.conf"
cp /fixtures/relay-443.conf "$NGX_PREFIX/conf/stream.d/"
cp /fixtures/sni.map "$NGX_PREFIX/conf/stream.d/relay-443/"
cp /fixtures/site.conf "$NGX_PREFIX/conf/conf.d/relay-site.example.com.conf"
cp /fixtures/reality.conf "$NGX_PREFIX/conf/conf.d/relay-cover.example.com.conf"
cp /fixtures/panel.conf "$NGX_PREFIX/conf/conf.d/relay-panel.conf"
cp /fixtures/relay-00-default.conf "$NGX_PREFIX/conf/conf.d/"
for domain in site.example.com cover.example.com panel.example.com; do
  mkdir -p "$NGX_PREFIX/conf/ssl/$domain"
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=$domain" -addext "subjectAltName=DNS:$domain" \
    -keyout "$NGX_PREFIX/conf/ssl/$domain/key.pem" -out "$NGX_PREFIX/conf/ssl/$domain/fullchain.pem" 2>/dev/null
done
nginx -p "$NGX_PREFIX" -c "$NGX_PREFIX/conf/nginx.conf" -g 'load_module /usr/lib/nginx/modules/ngx_stream_module.so;' -t

xray version
xray run -test -c /fixtures/xray.json
