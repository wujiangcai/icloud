# Docker Compose 部署

Compose 会一次启动三个服务：

- api：FastAPI/Uvicorn HTTP API
- worker：IMAP 同步和批量生成任务处理器
- proxy：Caddy 反向代理，负责对外提供 HTTP/HTTPS

API 只在 Compose 内部网络暴露，宿主机访问统一经过 Caddy。

## 首次配置

在项目目录执行：

~~~powershell
Copy-Item .env.platform.example .env.platform
~~~

如果已经存在 .env.platform，不要覆盖它。至少确认以下配置：

- CADDY_DOMAIN=:80：本地 HTTP 调试
- CADDY_DOMAIN=panel.example.com：公网域名，Caddy 自动申请 HTTPS
- PLATFORM_PUBLIC_ORIGIN 与实际访问地址一致
- PLATFORM_MASTER_KEY 必须保持不变；已有数据库时不能重新生成
- 新部署不能保留示例中的 PLATFORM_MASTER_KEY 占位值；请填入有效 Fernet 密钥，或清空后让程序在 data/platform/platform_master.key 中自动生成

已有数据迁移时，把整个 data/platform 目录复制到项目目录，尤其保留：

~~~text
data/platform/platform.sqlite3
data/platform/platform_master.key
data/platform/platform_admin.key
~~~

.env.platform、CK/cURL、Cookie、App 专用密码和密钥不要提交到 Git。

## 一条命令启动

~~~powershell
docker compose --env-file .env.platform -f compose.platform.yaml up -d --build
~~~

查看服务状态：

~~~powershell
docker compose --env-file .env.platform -f compose.platform.yaml ps
docker compose --env-file .env.platform -f compose.platform.yaml logs -f api worker proxy
~~~

本地检查：

~~~powershell
curl http://127.0.0.1/health
~~~

管理页面：

~~~text
http://127.0.0.1/platform/admin
~~~

## 公网部署

1. 将 CADDY_DOMAIN 改成真实域名。
2. 将 PLATFORM_PUBLIC_ORIGIN 改成 https://真实域名。
3. 把域名 DNS 的 A/AAAA 记录指向服务器。
4. 放行 TCP 80 和 443。
5. 再执行启动命令，Caddy 会把证书保存到 caddy-data 卷。

公网更新同样执行：

~~~powershell
docker compose --env-file .env.platform -f compose.platform.yaml up -d --build
~~~

## Linux 备份与 R2 成本保护

Linux 生产机可选用仓库根目录的 [`deploy/`](../deploy/README.md) 文件：它提供
本机与 R2 的加密备份、恢复说明、Cloudflare 预算告警以及 15 分钟一次的 R2 用量监控。
这些文件需要 root-only Secret 环境文件，示例中不含任何实际令牌或 S3 密钥。

## 国内服务器与 Cloudflare Tunnel

国内服务器可以通过 Cloudflare Tunnel 使用自定义域名访问。推荐让
Cloudflare 在边缘终止 HTTPS，再由服务器上的 cloudflared 转发到本机 Caddy：

~~~text
用户 -> Cloudflare HTTPS -> cloudflared -> http://127.0.0.1:80 -> Caddy -> API
~~~

使用 Tunnel 时，环境文件可以设置为：

~~~dotenv
CADDY_DOMAIN=:80
PLATFORM_PUBLIC_ORIGIN=https://panel.example.com
~~~

Tunnel 的公共主机名指向：

~~~text
http://127.0.0.1:80
~~~

如果不需要服务器直接接受公网流量，可以把 proxy 端口限制为本机：

~~~yaml
ports:
  - "127.0.0.1:80:80"
  - "127.0.0.1:443:443"
~~~

Cloudflare Tunnel 不需要开放服务器入站 80/443，也不会替代域名备案或服务商要求；
国内访问速度和稳定性应使用实际运营商网络测试。使用 Tunnel 时不要把服务器真实 IP
公开到 DNS。

## 取码链接有效期

公开取码链接本身是长效的，数据库中没有独立的过期时间。链接会在以下情况失效：

- 手动撤销或重新生成公开链接；
- 对应邮箱或客户被停用；
- 对应数据被删除或数据库丢失。

PLATFORM_SESSION_TTL_SECONDS 默认 86400 秒，只控制管理员/客户登录会话，不控制公开取码链接。
PLATFORM_CODE_MAX_AGE_SECONDS 默认 3600 秒，只控制页面允许显示多旧的验证码；链接仍然有效，
但超过这个时间的旧验证码不会显示。

## 2 核 2 GB 服务器建议

2 核 2 GB 可以运行 API、单个 worker、Caddy 和 Cloudflare Tunnel，适合低并发、少量邮箱
和简单挂机程序。不要在同一台机器上启动多个 API worker 或多个 platform worker。

资源紧张时可以在 .env.platform 中使用：

~~~dotenv
PLATFORM_WORKER_INTERVAL_SECONDS=60
PLATFORM_HME_GENERATION_BATCH_LIMIT=5
PLATFORM_HME_GENERATION_COOLDOWN_MINUTES=60
~~~

邮箱生成保持每批 5 个，由 60 分钟冷却控制为每小时 5 个。只调高 worker
轮询间隔来降低后台空转开销；把批量上限改成 1 会直接降为每小时 1 个。

建议：

- 配置 1–2 GB swap，首次 Docker 构建和依赖安装时更稳；
- 保留至少 5 GB 可用磁盘空间；
- 如果其他程序长期占用超过约 1.2 GB 内存，或邮箱数量达到数百、批量生成持续运行，建议升级到 4 GB；
- 使用 docker stats 观察实时内存和 CPU，使用 Compose 日志排查 worker 是否反复失败。

~~~bash
docker stats
docker compose --env-file .env.platform -f compose.platform.yaml logs -f api worker proxy
~~~

## 停止与重启

~~~powershell
docker compose --env-file .env.platform -f compose.platform.yaml down
docker compose --env-file .env.platform -f compose.platform.yaml restart api worker proxy
~~~

down 不会删除 data/platform 和 Caddy 卷。只有确认不再需要数据时，才手动删除对应目录或卷。

## 注意事项

- 宿主机的 80/443 端口不能被其他程序占用。
- 切换到 Compose 前应停止同一数据目录上的本地 API 和 worker，避免两个 worker 同时同步或并发写 SQLite。
- 不需要再单独启动 platform_app.py 或 platform_worker.py；Compose 已分别管理 API 和 worker。
- worker 等待 API 健康检查通过后才启动。
- 当前环境没有 Docker 时无法在本机执行 build/up；在安装 Docker Desktop 或 Docker Engine 的机器上执行上面的命令即可。
