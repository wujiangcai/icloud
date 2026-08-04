# iCloud Code API

一个私有的 iCloud Hide My Email 收件管理服务。它通过 IMAP 读取你的主 iCloud 邮箱，把转发邮件按隐藏邮箱别名归类，并提供带 API Key 的验证码接口和本地后台。

## 需要准备

- 已开通 iCloud Mail 的邮箱地址
- Apple 账号的 App 专用密码，不是 Apple ID 登录密码
- 已经创建好的 Hide My Email 隐藏邮箱地址

iCloud IMAP 默认配置：

- Host: `imap.mail.me.com`
- Port: `993`
- SSL: enabled

## 启动

```powershell
cd E:\codex\icloud-code-api
python app.py
```

打开：

```text
http://127.0.0.1:8765/admin
```

首次启动会自动生成管理员 Key，保存在：

```text
E:\codex\icloud-code-api\data\secrets.json
```

也可以复制 `config.example.json` 为 `config.json` 后手动填写。

## 导入隐藏邮箱

后台支持单个添加，也支持批量导入：

```text
alias001@icloud.com
alias002@icloud.com----alias_custom_key
alias003@icloud.com----alias_custom_key----标签----备注
```

如果不写 alias key，系统会自动生成。

## API

每个隐藏邮箱都有自己的 API Key。

获取最新验证码：

```http
GET /api/v1/code?email=alias001@icloud.com&key=ALIAS_API_KEY
```

返回示例：

```json
{
  "ok": true,
  "code": "123456",
  "mail": {
    "id": 1,
    "alias_email": "alias001@icloud.com",
    "from": "noreply@example.com",
    "subject": "Your verification code",
    "received_at": "2026-06-21T00:00:00+00:00"
  }
}
```

## GuJumpgate 对接

GuJumpgate 已经有 `iCloud API` 邮箱服务入口。填：

- API 地址：`http://127.0.0.1:8765`
- API 密码：管理员 Key
- 自定义邮箱池：导入后台里的凭据格式

凭据格式：

```text
隐藏邮箱----该邮箱的 API Key
```

GuJumpgate 会请求：

```http
POST /api/verification-code
```

本服务已经兼容这个接口。

## 和 hidemyemail-generator 形成链路

`hidemyemail-generator` 负责创建 Hide My Email 地址，默认会把生成结果追加到它自己的 `emails.txt`。

导入到本后台：

```powershell
cd E:\codex\icloud-code-api
python import_hidemyemail_generator.py
```

创建并自动导入：

```powershell
cd E:\codex\icloud-code-api
python generate_and_import.py --count 5
```

这个命令会调用 `E:\codex\hidemyemail-generator\cli.py generate`，然后把新增的 `emails.txt` 内容导入后台。

完整链路建议是：

```text
hidemyemail-generator 创建隐藏邮箱
        ↓
icloud-code-api 导入并生成每个邮箱的 API Key
        ↓
GuJumpgate 自定义邮箱池使用 “邮箱----API Key”
        ↓
GuJumpgate 通过 iCloud API 自动读取验证码
```

后续如果要更紧密，可以把生成器改成创建成功后自动 POST 到：

```http
POST /api/aliases
```

## 注意

这个服务只读取你自己邮箱已经收到的邮件。苹果没有公开的 Hide My Email 独立收件箱 API，所以这里的“每个邮箱一个 API”是本服务基于转发邮件做出的虚拟收件箱。
