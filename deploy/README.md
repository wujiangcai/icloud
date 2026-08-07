# Linux production deployment

This directory contains the host-level Compose override, systemd units,
encrypted restic backup, and Cloudflare R2 cost monitoring used by the Linux
deployment.

## Prerequisites

Install Docker Engine with the Compose plugin, plus the host backup tools:

```bash
sudo apt-get update
sudo apt-get install -y restic python3-boto3
```

The checked-in defaults use `/home/ubuntu/icloud`. If the repository is
installed elsewhere, update that path in the systemd units and in
`monitor/r2-monitor.env`, or set the corresponding `ICLOUD_CODE_*` variables.

## Secrets

Never commit the completed environment files. Install the examples into a
root-only directory and then replace every placeholder:

```bash
sudo install -d -o root -g root -m 700 /etc/icloud-code-platform
sudo install -o root -g root -m 600 deploy/backup/backup-r2.env.example /etc/icloud-code-platform/backup-r2.env
sudo install -o root -g root -m 600 deploy/monitor/cloudflare-api.env.example /etc/icloud-code-platform/cloudflare-api.env
sudo install -o root -g root -m 600 deploy/monitor/r2-monitor.env /etc/icloud-code-platform/r2-monitor.env
sudo sh -c 'umask 077; openssl rand -base64 48 > /etc/icloud-code-platform/restic-password'
```

Use a scoped Cloudflare API token with account analytics and notifications
permissions. R2 S3 credentials belong only in `backup-r2.env`.

## Install services

```bash
sudo install -o root -g root -m 755 deploy/backup/icloud-code-platform-backup /usr/local/sbin/
sudo install -o root -g root -m 755 deploy/monitor/icloud-code-r2-monitor /usr/local/sbin/
sudo install -o root -g root -m 755 deploy/monitor/configure-cloudflare-budget-alert /usr/local/sbin/
sudo install -o root -g root -m 644 deploy/backup/*.service deploy/backup/*.timer deploy/monitor/*.service deploy/monitor/*.timer /etc/systemd/system/
sudo install -o root -g root -m 644 deploy/icloud-code-platform.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now icloud-code-platform.service icloud-code-platform-backup.timer icloud-code-platform-backup-maintenance.timer icloud-code-r2-monitor.timer
```

Initialize both restic repositories before enabling backups. See
[`backup/RESTORE.md`](backup/RESTORE.md) for backup and restore commands.

Create the account-wide Cloudflare budget alert after reviewing its threshold:

```bash
sudo bash -c 'set -a; . /etc/icloud-code-platform/cloudflare-api.env; set +a; /usr/local/sbin/configure-cloudflare-budget-alert'
```

Cloudflare budget alerts are informational. The R2 monitor adds a separate
server-side write guard for this deployment, but it cannot stop writes made by
other credentials or Cloudflare products.
