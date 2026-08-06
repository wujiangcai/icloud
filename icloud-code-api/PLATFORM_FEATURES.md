# 多 iCloud 账号与邮箱库存

当前生产平台继续使用 `platform_app.py`、`platform_worker.py` 和现有接码链接。新功能不会替换原有 `mailboxes/messages/public_access` 数据，而是在其上增加 Apple 账号归属和业务状态。

## 账号流程

1. 打开 `/platform/operator`，进入“iCloud 账号”。
2. 导入 `new-icloud` 支持的 CK/cURL 文本，服务端会校验并加密保存 CK。
3. 点击“同步隐藏邮箱”，Apple 返回的真实隐藏邮箱会按邮箱地址去重并归入该账号。
4. 在账号上配置一次主 iCloud 邮箱和 App 专用密码。
5. 后台 worker 每个 iCloud 账号只建立一次 IMAP 同步，邮件按收件人隐藏邮箱地址分配到库存记录。

隐藏邮箱本身不是 IMAP 登录账号；IMAP 使用主 iCloud 邮箱和 App 专用密码。

## 业务状态

邮箱的 `business_status` 与运行用的 `active` 分开：

- `inventory`：库存中
- `sold`：已卖出
- `self_member`：自用会员
- `self_no_member`：自用未开会员
- `disabled`：停用
- `trash`：失效/垃圾

客户 ID、订单号和备注都是可选字段，所以未分配客户的库存邮箱可以直接管理。

## 批量生成

- “生成一批”保留 `new-icloud` 的每批最多 5 个机制。
- “批量生成任务”可以设置目标总量，worker 会按账号冷却时间自动继续。
- 默认目标上限为 700，可用 `PLATFORM_HME_GENERATION_TARGET_MAX` 调整。
- 默认冷却 60 分钟，使用 `PLATFORM_HME_GENERATION_COOLDOWN_MINUTES` 调整。

## 大库存

库存接口默认服务端分页，每页 50 条，最多 100 条；支持账号、状态、验证码和关键词筛选。运营页面不会一次把几千条邮箱或每个邮箱的验证码请求全部加载到浏览器。

相关接口：

```text
GET   /api/v1/operator/icloud-accounts
POST  /api/v1/operator/icloud-accounts/import
POST  /api/v1/operator/icloud-accounts/{id}/sync
POST  /api/v1/operator/icloud-accounts/{id}/generate
POST  /api/v1/operator/icloud-accounts/{id}/generation-campaigns
GET   /api/v1/operator/mailboxes?page=1&page_size=50&status=inventory
PATCH /api/v1/operator/mailboxes/{id}/business
PATCH /api/v1/operator/mailboxes/batch-business
```
