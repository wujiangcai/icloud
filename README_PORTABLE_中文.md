# iCloud Hide My Email Workflow 迁移包

这个压缩包是干净版迁移包，已剔除隐私信息。

## 包含

- hidemyemail-generator：批量创建 iCloud 隐藏邮箱的脚本
- icloud-code-api：本地/服务器后台和验证码 API
- Windows 安装脚本
- 示例配置文件

## 已剔除的隐私信息

- iCloud cookie/session
- Apple ID / iCloud 主邮箱
- Apple App 专用密码
- Admin API Key
- 已生成邮箱列表
- SQLite 数据库
- 服务器 IP / 真实域名配置
- Python 虚拟环境缓存

## 在新电脑使用

### 1. 安装 Python

安装 Python 3.11 或 3.12，并勾选 Add Python to PATH。

### 2. 运行安装脚本

双击：

```bat
install_windows.bat
```

### 3. 配置 iCloud Cookie

把：

```text
hidemyemail-generator\cookie.txt.example
```

复制一份改名为：

```text
hidemyemail-generator\cookie.txt
```

然后登录 iCloud 网页，导出 cookie，粘贴进去。

### 4. 启动本地后台

双击：

```bat
start_local_admin.bat
```

浏览器打开：

```text
http://127.0.0.1:8765/admin
```

第一次运行会自动生成 Admin API Key，位置：

```text
icloud-code-api\data\secrets.json
```

### 5. 填写后台设置

在后台填：

- iCloud 邮箱：你的主 iCloud 邮箱
- App 专用密码：Apple 账号生成的 App 专用密码
- IMAP 主机：imap.mail.me.com
- 端口：993
- 邮箱目录：INBOX
- 验证码有效秒数：3600

### 6. 批量创建并导入

示例：

```bat
generate_and_import.bat 10
```

脚本会自动从 `icloud-code-api\data\secrets.json` 读取 Admin Key；也可以按
`COUNT ADMIN_KEY API_URL SUCCESS_DELAY FAILURE_DELAY` 顺序显式传入参数。

首次使用自动刷新 Cookie：

```powershell
hidemyemail-generator\.venv\Scripts\python.exe -m pip install -r hidemyemail-generator\requirements.txt
hidemyemail-generator\.venv\Scripts\python.exe hidemyemail-generator\refresh_cookie.py --headed
```

在打开的 Edge 窗口完成 iCloud 登录和验证一次。之后创建脚本和定时任务会
在创建邮箱前自动刷新并验证 Cookie；验证失败不会覆盖旧的 `cookie.txt`。

默认节奏：

- 成功后等待 100 秒
- 失败后等待 120 秒

也可以用定时任务脚本按自己的节奏运行。

### 7. 每 30 分钟自动创建

双击：

```bat
install_hme_schedule.bat
```

首轮创建 4 个，之后每 30 分钟创建 5 个。状态和日志保存在：

```text
icloud-code-api\data\hme_schedule_state.json
icloud-code-api\data\hme_schedule.log
```

卸载任务：

```bat
uninstall_hme_schedule.bat
```

### 8. API 格式

后台可导出：

```text
邮箱---接口地址
```

例如：

```text
example@icloud.com---http://127.0.0.1:8765/api/v1/code?email=example%40icloud.com&key=alias_xxx
```

## 注意

- 这个包不要放入真实 cookie.txt、config.json、data 目录后再发给别人。
- 如果要部署到服务器，需要自行配置域名、反向代理和 systemd。
- 旧手机号转发项目没有包含在这个包里，避免混入你的服务器私有配置和路由数据。
