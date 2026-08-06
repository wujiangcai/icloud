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
