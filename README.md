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

## 面板 HTTPS

先在面板配置 Cloudflare Token，再签发证书并换成 HTTPS 配置。面板每 12 小时检查一次，证书剩余 ≤30 天时自动续签。

```bash
docker exec vps-relay sh -c '[ -e /root/.acme.sh-admin ] || ln -s /root/.acme.sh/users/admin /root/.acme.sh-admin; CF_API_TOKEN=$(cat /etc/vps-relay/users/admin/cf-token) ACME_HOME=/root/.acme.sh-admin relay-acme <面板域名> issue'
bash deploy/render-panel-conf.sh <面板域名> templates/panel-ssl.conf.tmpl | sudo tee /usr/local/nginx/conf/conf.d/relay-panel.conf >/dev/null
sudo /usr/local/nginx/sbin/nginx -p /usr/local/nginx -c conf/nginx.conf -t && sudo /usr/local/nginx/sbin/nginx -s reload
```

## 更新

```bash
cd vps-relay
git pull
docker compose build --no-cache
docker compose up -d
```

## 443 SNI 分流与 Reality 入口（M15）

边缘机 443 可切换为 Nginx stream 的 `ssl_preread` 分流：普通 HTTPS 站点和面板转到本机 `127.0.0.1:8443`，仍保留真实客户 IP；Reality 专用域名统一转到面板容器内托管的 Xray（本机 30001）。前端 Xray 接受客户端连接，再使用粘贴的后端 VLESS Reality 参数做链式转发。Reality 回落在前端本机的证书和静态伪装站完成，后端不需要任何改动。历史 `stream.d/relay-tcp-*.conf` 保持原样，面板不再提供四层 TCP 转发管理；SNI 迁移与恢复继续按原规则处理。

宿主 Nginx 必须带 `--with-stream_ssl_preread_module`，stream 块需引入 `stream.d/*.conf`。`.github/workflows/nginx.yml` 提供与线上参数一致的 Nginx 1.28.0 构建产物，宿主二进制由管理员另行更换。新装机仍使用普通 HTTPS 模式。

SNI 模式由面板管理 `conf.d/relay-00-default.conf`：未知域名或 IP 的 HTTP 请求返回 444，无 SNI 或未知 SNI 的 TLS 握手直接拒绝，避免暴露业务站点；已知站点及其 ACME http-01 透传照常匹配。迁移前若现有配置含 `default_server` 则拒绝开启，请先处理冲突；回退普通模式时删除此默认站点。

```bash
# 查看模式及所有状态的 Reality 入口数量
docker exec vps-relay vps-relay sni443 status
# 中断迁移后，先还原备份并核验旧模式
docker exec vps-relay vps-relay sni443 recover
# 开启 SNI 分流
docker exec vps-relay vps-relay sni443 enable
# 删除所有 Reality 入口后回退普通 HTTPS
docker exec vps-relay vps-relay sni443 disable
```

迁移先检查宿主模块、stream include、8443 占用及非托管配置的 443 监听，原文件与新文件清单备份到 `/etc/vps-relay/backup/sni443-<UTC 时间>/`。启用、停用和待删除的托管站点及 HTTPS 面板都会重渲染，纯 HTTP 面板保持原样。检查、重载或 15 秒内的已知域名证书核验、未知域名握手拒绝核验失败会自动还原并核验旧模式。迁移与 API 写操作、自动续期互斥。迁移修改配置前将进度写入备份的 `manifest.json`，核验后标记 `done`；进度为 `in-progress` 时，状态命令会提示先 `recover`，面板继续提供读取，但暂停 Xray 启动、配置写操作及证书续期重载。恢复成功标记 `recovered`，恢复未通过可再次运行 `recover`。面板 HTTPS 应在迁移前配置好。

管理员在“④ Reality 入口（共用 443）”中选择专用子域名并粘贴后端链接即可创建。面板使用当前管理员的 Cloudflare Token 接管或新建 DNS only A 记录并签发真实证书，默认伪装页位于 `/usr/local/nginx/html/relay-camouflage/index.html`，已有页面不会覆盖。后端仅支持公网 IP、VLESS Reality TCP，flow 为空或 `xtls-rprx-vision`，必须包含 sni 和 pbk。客户端使用导出的新链接；**Clash/mihomo 需开启 `reality-opts.support-x25519mlkem768`**。

前端身份独立于后端：首次生成的 X25519 密钥和 shortId 保存在 `/etc/vps-relay/xray/keys.json`，每入口的前端 UUID 和后端出站机密保存在 `xray/entries/<domain>.json`，生成配置为 `xray/config.json`（均位于 `/etc/vps-relay/`，目录 700、文件 600）。导出链接保存于 `/etc/vps-relay/reality-links/<domain>.link`（目录 700、文件 600）。公开的 Nginx `relay-meta` 不含 UUID 或密钥。

Xray 配置仅在内容变化时校验并应用，配置不变不校验、不重启；启动前检查 30001 未被其他进程占用，启动后最多等待 5 秒确认本机端口可连接，故障显示在入口状态中。Nginx 重载成功后，监督器已接收的配置按退避重试；读配置或控制 socket 通知失败等尚未提交的配置，由运行中的面板每 30 秒对账补偿。运行摘要一致时对账不重启 Xray，不回退普通站点；新建 Reality 入口必须确认 Xray 就绪，否则撤销。增删、启停入口会重启共享 Xray 并断开现有 Reality 连接；没有启用入口时停止子进程，异常退出按 1–30 秒退避重试。**重建或重启面板容器会断开正在使用的 Reality 连接**。仅管理员可创建、导出、启停和删除入口，上游更改需删除重建；存在任何状态的 Reality 入口时禁止关闭 SNI 模式。8443 和 30000–30999 为本机内部监听保留，迁移继续拒绝占用这些端口的历史 stream 配置。

手工执行 `relay-acme` 的 issue、renew、remove 都先通过 `vps-relay lock-run -- ...` 取得配置目录锁并检查迁移记录，整个脚本期间持锁；取锁失败或存在 `in-progress` 时直接以非零状态退出，不写证书或 ACME 状态。面板调用时继承并验证真实锁描述符，环境变量本身不能绕过锁。面板发起的 ACME 操作运行在独立进程组中，超时会结束整个进程组并等待退出，再释放配置锁。直接执行 `nginx-reload` 若取锁失败也会报错退出，可待锁释放后重试。

证书操作先在隔离副本中执行，全部成功并校验证书与私钥匹配后才发布；失败恢复原证书及 ACME 状态，手工 remove 也不能删除仍被活动配置引用的证书。发布进度存于 `backup/acme-*/manifest.json`，中断后由下一次配置操作、启动或周期对账恢复。配置写操作在首次修改前用 `nginx-pending.json` 保存快照，日志仅表示一个操作尚未完成。全部成功，或失败后已完整回滚并重新加载，才显式标记一致并删除日志。DNS 切换前先保留已加载的站点及恢复元数据；DNS 回滚失败时保留现场并立即结束日志。删除站点在隔离配置并重载成功后、永久删除证书或入口机密之前结束日志，证书子事务也在提交清单前结束借用的父日志；后续清理失败保留现场供重试，不能再恢复引用已删除材料的活动配置。边界后的新一轮配置变更以安全现场重新取快照；DNS 结果补记与非活动删除备份的清理只做原子操作，不重新开启日志或触发额外 HUP。进程中断或回滚失败留下的日志由下次对账恢复快照、执行 `nginx -t` 和 HUP，成功后删除；恢复可重入，损坏记录保留现场并报错。重载语义与 M14.2 一致：语法检查通过且信号送达即成功，宿主 Nginx 拒绝重载而继续运行旧配置的情况，普通操作不做额外检测；SNI 迁移另有端口及 TLS 核验。SNI 回退会恢复未改动站点的原始字节及权限，并删除空的 `stream.d/relay-443/` 目录。

入口机密缺失、不可读或损坏时，仅该入口暂停并从 SNI map 与 Xray 配置排除；完整 Xray 配置校验失败时会逐入口独立校验，暂停有问题的入口并重新校验剩余配置，全部失败或共享配置仍失败时暂停全部入口并停止 Xray。共享 `keys.json` 故障也会暂停全部入口。普通站点和证书续期继续工作，Reality 卡片使用状态接口显示暂停原因、Xray 运行状态和最近错误；语义校验的脱敏原因与配置摘要保存在 `xray/health.json`（600）。请恢复原机密文件并执行一次配置操作使其重新同步；存在入口时不会因密钥文件缺失而静默生成另一套密钥。新建入口会提前校验后端指纹 `fp`，缺省为 `chrome`，不接受不支持的指纹值。

API：`GET /api/reality` 返回 `sni_mode`、`xray_running`、`xray_error` 和入口列表 `entries`（每入口含 `reality_error`、`reality_paused`）；`POST /api/reality` 接受 `{domain, link, label}`；`GET /api/reality/{domain}/link` 重新导出链接。启停与删除沿用站点 API。

## 许可证

MIT
