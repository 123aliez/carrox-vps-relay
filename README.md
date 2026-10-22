# vps-relay

极简反代加速面板。部署在 CN2/精品线路 VPS 上，为普通线路上的服务提供 L7 反代加速，自动完成 DNS 配置、证书签发和 Nginx 配置。

## 功能

- **一键建站**：填入加速域名 + 上游地址，自动接管已有 A 记录或创建缺失记录、签发 Let's Encrypt 证书、渲染 Nginx 配置并热重载
- **多用户支持**：管理员可通过面板或 API 创建用户密钥，每个用户独立管理自己的 Cloudflare Token 和站点
- **站点隔离**：普通用户只能看到和操作自己创建的站点，管理员可管理所有站点
- **自动续签**：每 12 小时扫描，证书剩余 ≤30 天时自动续签
- **WebSocket/SSE 透传**：默认支持，无需额外配置
- **无数据库**：所有状态存储在 Nginx 配置文件的 `relay-meta` 注释中，文件即真相
- **证书脱敏**：CF Token 在界面中脱敏显示

## 环境要求

宿主机需已具备：

- **Nginx** ≥ 1.28（需编译 http_ssl / http_v2 / http_v3 / stream / http_realip 模块）
- **Docker** + **Docker Compose**
- 公网 80 / 443 端口可达
- Cloudflare 账号（用于 DNS 管理）

其余依赖（Go、acme.sh、jq、dig、openssl 等）全部封装在 Docker 镜像内。

## AI 部署

如果是让 AI 代理或自动化脚本直接部署，请优先阅读：

- `AI_DEPLOY.md`

该文档说明了无交互部署约束、`--domain` 参数、fallback 行为以及部署后的标准验证步骤。

## 快速部署

```bash
# 1. 克隆项目
git clone https://github.com/AiCarrox/vps-relay.git
cd vps-relay

# 2. 一键部署（无域名，面板走本机 HTTP）
bash deploy/install.sh

# 3. 一键部署（有域名，面板走域名 HTTP）
bash deploy/install.sh --domain relay.example.com
```

部署完成后，终端会输出管理员密钥和面板地址。首次启动时程序会自动生成一个管理员密钥并打印到日志中。

```
============================================
  vps-relay 部署完成
============================================

  面板地址:   http://127.0.0.1:8787
  # 或（使用 --domain 时）
  面板地址:   http://relay.example.com
  边缘 IP:    1.2.3.4
  管理员密钥: Kj8mN2pQ5xRt

  ⚠  请立即登录面板，配置 Cloudflare API Token。
  ⚠  可通过面板「密钥管理」为其他用户创建密钥。
============================================
```

## DNS 接管与恢复（M13）

新建反代时，程序先通过 DNS-01 准备证书，再写入、检查并加载 Nginx 配置，最后切换 DNS：

- 存在唯一 A 记录：原地更新同一个记录 ID 到中转 IPv4，并设为 DNS only；保存原 IP、TTL 和代理状态。
- 已指向本机且为 DNS only：直接复用，失败回滚和删除站点均保留该记录。
- 不存在 A 记录：新建；回滚或删除时只删除本次创建的记录。
- 查询失败、同名多 A、AAAA 或 CNAME：明确报错，避免重复记录或部分流量绕过中转。

接管记录的原值及来源保存于配置文件的 `relay-meta.dns`。删除接管站点时恢复原记录；DNS 恢复失败或检测到外部修改时保留站点，处理后可重试。旧版站点缺少来源信息，删除时保留其 DNS 和来源不明的证书。程序只注销并清理能够确认由本面板新建的本地证书，不执行证书吊销。

例如，原来 `redvpn.example.com` 指向 `23.95.8.179`，中转机为 `38.6.76.28`：加速域名前缀填 `redvpn`、选择 `example.com`，上游填 `https://23.95.8.179`（默认 443）。创建后原 A 记录更新为中转 IP，Nginx 继续访问原 IP，并保留入口域名的 Host/SNI。上游不能填写加速域名自身或本机 IP。

记录来源在 DNS 写入前保存，切换时再次检查原记录。若新建请求响应丢失，无法可靠获得新记录 ID，程序会保留反代和恢复信息并报告不确定状态，要求核对 Cloudflare，禁止猜测并删除记录。外部 DNS 写入仍可能与检查并发，程序不能提供跨系统的原子互斥。

每个用户的 acme.sh 状态实际保存在持久卷 `/root/.acme.sh/users/{key_id}`，操作证书时建立 `/root/.acme.sh-{key_id}` 兼容链接。升级旧版前须迁移原容器临时层中的用户目录，避免重建丢失续期状态。

## 多用户管理

### 通过面板

管理员登录后，在底部「密钥管理」卡片中：

1. 输入用户 ID 和备注，点击「创建」
2. 复制生成的密钥，分发给对应用户
3. 用户登录后配置自己的 Cloudflare API Token 即可使用

### 通过 API

```bash
# 创建用户密钥（需 admin cookie 或 Bearer token）
curl -X POST http://127.0.0.1:8787/api/keys \
  -H 'Content-Type: application/json' \
  -b 'vps-relay-auth=<admin-key>' \
  -d '{"id":"user01","role":"user","note":"用户01"}'

# 列出所有密钥（key 脱敏）
curl http://127.0.0.1:8787/api/keys -b 'vps-relay-auth=<admin-key>'

# 删除密钥
curl -X DELETE http://127.0.0.1:8787/api/keys/user01 \
  -b 'vps-relay-auth=<admin-key>'
```

## API 列表

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/healthz` | 健康检查 |
| POST | `/api/login` | 登录（body: `{"token":"<key>"}`） |
| GET | `/api/whoami` | 当前用户信息 |
| GET | `/api/cf-token/status` | CF Token 状态（脱敏） |
| PUT | `/api/cf-token` | 保存 CF Token |
| GET | `/api/zones` | 列出 Cloudflare Zone |
| GET | `/api/sites` | 列出站点（admin 看全部） |
| POST | `/api/sites` | 创建站点 |
| PUT | `/api/sites/{domain}` | 编辑上游地址 |
| POST | `/api/sites/{domain}/toggle` | 启用/停用站点 |
| DELETE | `/api/sites/{domain}` | 删除站点 |
| POST | `/api/sites/adopt` | 接管已有 Nginx 配置 |
| GET | `/api/keys` | 列出密钥（admin only，脱敏） |
| POST | `/api/keys` | 创建密钥（admin only） |
| DELETE | `/api/keys/{key_id}` | 删除密钥（admin only） |

## 目录约定

| 路径 | 用途 |
|------|------|
| `/etc/vps-relay/keys.json` | 密钥表（程序自动管理） |
| `/etc/vps-relay/users/{id}/cf-token` | 用户私有 Cloudflare Token |
| `/usr/local/nginx/conf/conf.d/relay-*.conf` | 站点配置 |
| `/usr/local/nginx/conf/ssl/{domain}/` | TLS 证书 |

## 更新

```bash
cd vps-relay
git pull
docker compose build --no-cache
docker compose up -d
```

## 许可证

MIT
