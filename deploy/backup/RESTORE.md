# iCloud Code Platform 备份与恢复

远端备份写入由 R2 用量监控保护：总存储达到 7 GB 时管理后台告警，达到
8 GB 或操作次数硬限制时停止新的 R2 写入，本地备份仍会继续。阈值配置位于
`/etc/icloud-code-platform/r2-monitor.env`。

## 备份范围

每个加密快照包含：

- `platform.sqlite3` 的 SQLite 在线一致性快照；
- `platform_master.key` 和 `platform_admin.key`；
- `.env.platform`、`compose.platform.yaml` 和 `Caddyfile`（存在时）；
- 文件 SHA-256 与 SQLite 完整性结果清单。

本地加密仓库位于 `/var/backups/icloud-code-platform/restic`，异地仓库位于 R2 Bucket
`icloud-code-platform-backups` 的 `restic/` 前缀。恢复密码由
`/etc/icloud-code-platform/restic-password` 提供，供下载保存的副本位于
`/home/ubuntu/icloud-code-backup-recovery-key.txt`。

## 查看快照

```bash
sudo bash -c 'set -a; . /etc/icloud-code-platform/backup-r2.env; set +a; restic -r "$R2_REPOSITORY" snapshots'
```

## 安全恢复演练（不覆盖线上数据）

```bash
sudo install -d -m 700 /var/lib/icloud-code-platform-backup/restore-test
sudo bash -c 'set -a; . /etc/icloud-code-platform/backup-r2.env; set +a; restic -r "$R2_REPOSITORY" restore latest --tag icloud-code-platform --target /var/lib/icloud-code-platform-backup/restore-test'
```

恢复到生产环境前必须先停止 iCloud API 和 worker 容器，只替换数据库与两把平台密钥，
设置所有者为容器用户 `10001:10001` 后再启动并验证。此操作不需要也不应停止
`azure-vm-bot.service`。不要在未验证恢复目录和快照内容前覆盖生产数据。
