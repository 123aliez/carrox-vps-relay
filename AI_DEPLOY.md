# AI 部署说明

本文件用于让 AI 代理或自动化脚本在尽量少交互的前提下，把 `vps-relay` 部署到一台已经安装好 Nginx 与 Docker 的 VPS。

## 适用范围

适用于以下前提：

- 宿主机已安装 **Nginx 1.28+**
- 宿主机已安装 **Docker** 且 `docker compose` 可用
- 宿主机 Nginx 安装路径为 `/usr/local/nginx`
- 宿主机允许写入：
  - `/usr/local/nginx/conf/nginx.conf`
  - `/usr/local/nginx/conf/conf.d/`
  - `/etc/vps-relay/`
- 部署用户具备 root 权限

如果宿主机是按 `vps-manager` 的 base/nginx 脚本初始化，通常满足上述要求。

## 设计约束

AI 在部署时应遵守以下规则：

- **不得覆盖**已有业务站点配置
- 只允许：
  - 增量补充 `nginx.conf` 中缺失的 `connection_upgrade` map
  - 增量补充 `nginx.conf` 中缺失的 `stream` 块（引入 `stream.d/*.conf`，用于 TCP 转发）
  - 新增 `relay-panel.conf`
  - 新增 `/etc/vps-relay/*`
  - 构建并启动 `vps-relay` 容器
- 如果发现目标域名已被其他 Nginx 配置占用，必须立即停止
- 如果 `nginx -t` 失败，必须恢复原始 `nginx.conf`

## 推荐部署命令

### 1. 有面板域名

```bash
bash deploy/install.sh --domain relay.example.com
```

行为：

- 自动检查 Nginx / Docker / Docker Compose
- 若 `nginx.conf` 缺少 `connection_upgrade` 或 `stream` 块，自动补齐
- 新增 `/usr/local/nginx/conf/conf.d/relay-panel.conf`
- 面板通过 `http://relay.example.com` 访问
- 构建并启动 `vps-relay`

### 2. 无面板域名

```bash
bash deploy/install.sh
```

行为：

- 不创建 `relay-panel.conf`
- 只启动容器
- 面板通过 `http://127.0.0.1:8787` 访问

## 部署后必须验证

AI 在部署完成后，至少应验证以下项目：

```bash
/usr/local/nginx/sbin/nginx -t
curl -sf http://127.0.0.1:8787/api/healthz
docker inspect -f '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}' vps-relay
```

如果部署使用了 `--domain`，再额外验证：

```bash
curl -H 'Host: relay.example.com' http://127.0.0.1/
```

## 关键文件

- 安装脚本：`deploy/install.sh`
- Nginx fallback 补丁器：`deploy/patch-nginx-map.py`
- 面板 vhost 模板：`templates/panel.conf.tmpl`
- 面板后端监听：`127.0.0.1:8787`

## 失败处理原则

### 1. `nginx.conf` 缺少 `connection_upgrade`

这是预期内情况，安装脚本会自动补齐，不需要人工中断。

### 2. `nginx -t` 失败

必须立即停止，并恢复原始 `nginx.conf`。

### 3. 域名冲突

如果 `--domain` 指定的域名已经被其他 `conf.d/*.conf` 使用，必须停止，不得覆盖。

### 4. 容器已存在

允许重跑部署脚本。脚本应支持幂等重建和重启。

## 当前已验证结论

本项目已在真实 VPS 上验证通过以下场景：

- 首次部署成功
- 自动补齐 `connection_upgrade` 成功
- `--domain relay.6553602.xyz` 成功创建面板 vhost
- 二次重跑部署脚本成功（幂等）

因此，后续 AI 部署应优先直接使用本文件与 `deploy/install.sh`，不再依赖源码外部文档。
