# iCloud Code Platform（多租户 MVP）

这是一个独立于旧版单租户 API 的多租户收件取码服务。设计参考了 `new-icloud` 项目的邮箱库存、后台同步、验证码展示和公开查看页，但没有复用其 CK/浏览器 Cookie 逻辑。

公开服务调研结论见 [PUBLIC_SERVICE_RESEARCH.md](PUBLIC_SERVICE_RESEARCH.md)：没有找到 Apple 官方的第三方通用验证码读取 API；示例站点均按第三方服务处理，本平台不依赖它们。

## 已实现

- 客户注册、登录、Bearer Session，租户数据按 `tenant_id` 隔离。
- 每个 iCloud 邮箱独立 `X-Mailbox-Key`；数据库只保存 API Key 哈希。
- 只接受 iCloud **App 专用密码**，使用 Fernet 加密保存；不接受 Apple ID 主密码、Cookie 或浏览器会话。
- IMAP SSL 同步最近邮件，自动提取常见 4–8 位验证码。
- 独立后台 worker 定时同步；没有真实测试邮箱时不要执行同步。
- 可撤销的公开查看页和 JSON 接口。公开链接只携带随机不透明令牌，不把邮箱地址或邮箱 API Key 放进 URL。
- 统一安全响应头、请求体限制、基础限流、审计事件和禁用缓存。
- 可选接入 Cloudflare R2：启用后将原始 MIME 邮件归档到私有 bucket，不把 R2 凭据或对象内容暴露给客户 API。
- 独立管理员控制台：客户、邮箱库存、同步、取码、链接发货、链接撤销和停用操作集中在 `/platform/operator`；添加邮箱时客户绑定可选，未分配的邮箱会进入平台库存。

## 本地启动

在此目录执行：

```powershell
cd C:\Users\caiwujiang\Desktop\项目\icloud\icloud-code-api
python -m venv .venv-platform
.\.venv-platform\Scripts\python.exe -m pip install -r requirements-platform.txt
$env:PLATFORM_MASTER_KEY = (& .\.venv-platform\Scripts\python.exe -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
$env:PLATFORM_PUBLIC_ORIGIN = "http://127.0.0.1:8766"
.\.venv-platform\Scripts\python.exe -m uvicorn platform_app:app --host 127.0.0.1 --port 8766
```

第二个终端运行自动同步器：

```powershell
cd C:\Users\caiwujiang\Desktop\项目\icloud\icloud-code-api
$env:PLATFORM_MASTER_KEY = "与 API 进程相同的密钥"
.\.venv-platform\Scripts\python.exe platform_worker.py
```

也可以直接执行 `run_platform.bat` 启动 API；它不会自动启动 worker，避免在 Windows 上重复启动多个调度器。

打开：

- 后台：<http://127.0.0.1:8766/platform/admin>
- 管理员控制台：<http://127.0.0.1:8766/platform/operator>
- Swagger：<http://127.0.0.1:8766/docs>
- 健康检查：<http://127.0.0.1:8766/health>

首次本机启动且未设置 `PLATFORM_ADMIN_KEY` 时，管理员密钥会生成到 `data/platform/platform_admin.key`。管理员无需先创建客户；在邮箱库存中添加邮箱时可选择客户，也可放入平台库存，点击“生成发货信息”后，复制下面两行给客户即可：

```text
邮箱名：name@icloud.com
接码地址：https://你的域名/public/mail/<PUBLIC_TOKEN>
```

客户打开接码地址即可看到最新验证码，页面自动刷新并提供复制验证码按钮；客户不需要注册或登录。

生产环境必须把 `PLATFORM_HOST` 设为 `0.0.0.0`，通过 HTTPS 反向代理暴露，并将 `PLATFORM_PUBLIC_ORIGIN` 设置为最终 HTTPS 域名。

## Docker Compose 启动

已提供 api、worker 和 Caddy proxy 的完整编排。首次配置和域名/数据迁移说明见 [DOCKER_DEPLOY.md](DOCKER_DEPLOY.md)。

~~~powershell
Copy-Item .env.platform.example .env.platform
docker compose --env-file .env.platform -f compose.platform.yaml up -d --build
~~~

本地默认通过 http://127.0.0.1 访问；生产环境把 CADDY_DOMAIN 和 PLATFORM_PUBLIC_ORIGIN 改为实际域名。

## 客户 API

注册或登录：

```http
POST /api/v1/auth/register
Content-Type: application/json

{"email":"customer@example.com","password":"至少八位的客户密码"}
```

添加邮箱。`api_key` 只在这次响应中显示：

```http
POST /api/v1/mailboxes
Authorization: Bearer <SESSION>
Content-Type: application/json

{"email":"name@icloud.com","app_password":"<iCloud App 专用密码>","label":"客户一号"}
```

取码接口：

```http
GET /api/v1/code?mailbox_id=<MAILBOX_ID>
X-Mailbox-Key: <MAILBOX_API_KEY>
```

返回示例：

```json
{"ok":true,"code":"","mail":null}
```

没有新邮件时 `code` 为空。客户服务端应轮询并使用 `after=<Unix 时间戳>` 避免重复读取旧码。

## 公开查看页

管理端调用：

```http
POST /api/v1/mailboxes/<MAILBOX_ID>/public-access
Authorization: Bearer <SESSION>
```

响应中的 `viewer_url` 和 `api_url` 只返回一次令牌。公开接口为：

```http
GET /api/v1/public/mail/<PUBLIC_TOKEN>/latest
GET /public/mail/<PUBLIC_TOKEN>
```

重置公开链接再次调用 `POST`；撤销调用 `DELETE /api/v1/mailboxes/<MAILBOX_ID>/public-access`。公开接口不返回 App 专用密码或邮箱 API Key，且设置 `no-store` 和 `no-referrer`。

## Cloudflare R2 接入

平台使用 S3 兼容接口，R2 客户端按需初始化；没有完整配置时不会发起网络请求。先创建**私有** R2 bucket，再在服务器的私有 `.env.platform` 中填写：

```dotenv
R2_ENDPOINT=https://<account-id>.r2.cloudflarestorage.com
R2_BUCKET=<private-bucket>
R2_ACCESS_KEY_ID=<new-access-key>
R2_SECRET_ACCESS_KEY=<new-secret>
R2_REGION=auto
R2_PREFIX=icloud-mail
R2_REQUIRED=false
R2_ARCHIVE_ENABLED=true
R2_MONTHLY_MAX_PUTS=900000
R2_MONTHLY_MAX_BYTES=9000000000
R2_MAX_OBJECT_BYTES=5242880
```

同步邮件时，平台会按租户、邮箱和 IMAP UID 的 SHA-256 路径归档原始 `.eml`；SQLite 保存对象 Key 和归档错误，不保存 R2 密钥。默认本地安全上限为每月 90 万次 PUT、9 GB 上传量和单个对象 5 MB，低于 R2 免费额度；达到上限后自动停止归档但仍继续取码。`R2_REQUIRED=false` 时归档失败不会阻断 IMAP 取码，`true` 时归档失败会让该次同步失败。新凭据应写入服务器 Secret/私有环境文件，不要粘贴到聊天、Git 或日志中。

## 数据与备份

默认数据目录为 `data/platform`：

- `platform.sqlite3`：租户、邮箱元数据、验证码和审计记录。
- `platform_master.key`：解密 App 专用密码所需的主密钥。

必须同时备份数据库和主密钥；只丢失主密钥会导致已保存的 App 专用密码不可恢复。生产环境建议将主密钥放在 Secret Manager，并使用 PostgreSQL/Redis 替换 SQLite/进程内限流。

## 上线前还需要补齐

当前版本是可运行 MVP，不是完整计费 SaaS。正式商业化前应增加邮箱/手机验证、管理员审批、套餐与计费、额度与并发限制、PostgreSQL、Redis 限流/队列、集中日志、告警、数据保留策略、备份恢复演练、反向代理 HTTPS 和滥用处理流程。

不要把任何 Cloudflare Token、R2 Secret、Apple ID 密码或 App 专用密码写进代码、`.env.example`、Git、截图或日志。此前在对话中暴露的 Cloudflare 凭据必须在 Cloudflare 控制台立即撤销并重新生成，旧值不要再使用。
